// Sources/AuthKit/AuthService.swift
import Foundation
import Combine
@preconcurrency import FirebaseAuth // Keep for non-Sendable handling
import UIKit

@MainActor
public class AuthService: ObservableObject, AuthServiceProtocol {
    @Published public private(set) var state: AuthState = .signedOut
    @Published public private(set) var lastError: AuthError? = nil

    // Explicit publishers for protocol conformance
    public var statePublisher: Published<AuthState>.Publisher { $state }
    public var lastErrorPublisher: Published<AuthError?>.Publisher { $lastError }

    private let config: AuthConfig
    private let firebaseAuthenticator: FirebaseAuthenticator
    private let biometricAuthenticator: BiometricAuthenticator
    private let secureStorage: SecureStorageProtocol

    private var authStateHandle: AuthStateDidChangeListenerHandle?
    private var cancellables = Set<AnyCancellable>()
    private var emailForLinking: String? // Stores email during linking flow

    public init(config: AuthConfig) {
        self.config = config
        let storage = KeychainStorage(); self.secureStorage = storage
        self.firebaseAuthenticator = FirebaseAuthenticator(config: config, secureStorage: storage)
        self.biometricAuthenticator = BiometricAuthenticator(); print("AuthService: Initializing.")

        // Setup listener
        authStateHandle = Auth.auth().addStateDidChangeListener { [weak self] (_, user) in
            Task { @MainActor [weak self] in // Dispatch listener callback to MainActor
                self?.handleAuthStateChange(firebaseUser: user)
            }
        }

        // Initial state check
        Task { @MainActor [weak self] in // Ensure initial check runs on MainActor
            // --- FIX: Remove unnecessary await ---
            self?.handleAuthStateChange(firebaseUser: Auth.auth().currentUser)
            // --- End FIX ---
        }
        print("AuthService: Init complete, listener added.")
    }

    deinit {
        print("AuthService: Deinit started.")
        // Schedule a task on the MainActor to perform the cleanup.
        // Capture self weakly to avoid prolonging lifetime unnecessarily.
        Task { @MainActor [weak self] in
            // Check if self still exists when the task runs
            guard let strongSelf = self else {
                print("AuthService: Deinit cleanup task ran after self was deallocated.")
                return
            }
            // Now safely access the MainActor-isolated property
            if let handle = strongSelf.authStateHandle {
                print("AuthService: Removing Firebase Auth state listener on MainActor.")
                Auth.auth().removeStateDidChangeListener(handle)
                // It's good practice to nil out the handle after removing,
                // although self is being deinitialized anyway.
                strongSelf.authStateHandle = nil
            } else {
                print("AuthService: No listener handle found during deinit task.")
            }
        }
        print("AuthService: Deinit finished scheduling cleanup task.") // Deinit returns *before* cleanup runs
    }


    // MARK: - Public API (@MainActor)
    public func signIn(from viewController: UIViewController) async {
        print("AuthService: signIn requested. State: \(state)")
        guard state.allowsSignInAttempt else { print("AuthService: Sign-in not allowed."); return }
        if state == .signedOut || state == .requiresBiometrics { resetForNewSignInAttempt() }
        let msg = state.isPendingResolution ? "Signing in..." : "Starting sign in..."; state = .authenticating(msg); lastError = nil
        var dismiss = true
        do { let user = try await firebaseAuthenticator.presentSignInUI(from: viewController); await completeSuccessfulSignIn(user: user) }
        catch let e as AuthError { await handleSignInAuthError(e); if state.isPendingResolution || e == .cancelled { dismiss = false } }
        catch { handleSignInGenericError(error) } // Catch generic error
        if state.isPendingResolution { dismiss = false }; if dismiss { print("AuthService: Dismissing UI."); viewController.dismiss(animated: true) } else { print("AuthService: UI remains for state: \(state).") }
    }

    public func signOut() {
        print("AuthService: signOut requested."); do { try Auth.auth().signOut(); clearLocalUserData(); print("AuthService: Sign out OK.") }
        catch { print("AuthService: Sign out failed: \(error)"); lastError = AuthError.makeFirebaseAuthError(error); state = .signedOut; clearLocalUserData() }
    }

    public func authenticateWithBiometrics(reason: String = "Sign in to your account") async {
        print("AuthService: Bio requested. State: \(state)")
        guard state == .requiresBiometrics else { print("Auth Warning: Bio requested but not required."); return }
        guard let uid = Auth.auth().currentUser?.uid else { print("Auth Error: Bio required but no user."); state = .signedOut; clearLocalUserData(); return }
        state = .authenticating(biometricAuthenticator.biometryTypeString); lastError = nil
        do { try await performBiometricAuthentication(reason: reason); print("AuthService: Bio successful.")
            if let u = Auth.auth().currentUser, u.uid == uid { let user = User(firebaseUser: u); if !user.isAnonymous { try? secureStorage.saveLastUserID(user.uid) }; state = .signedIn(user); print("AuthService: State -> signedIn.") }
            else { print("Auth Warning: User changed during bio?"); state = .signedOut; clearLocalUserData() }
        } catch let e as AuthError { print("AuthService: Bio failed: \(e)"); self.lastError = e; self.state = .requiresBiometrics }
        catch { print("AuthService: Unexpected bio error: \(error)"); self.lastError = .unknown; self.state = .requiresBiometrics }
    }

    public func proceedWithMergeConflictResolution() async {
        print("AuthService: proceedWithMerge. State: \(state)")
        guard state == .requiresMergeConflictResolution else { print("Auth Warning: Not in merge state."); return }
        guard let cred = firebaseAuthenticator.existingCredentialForMergeConflict else { print("Auth Error: Missing merge cred."); state = .signedOut; lastError = .missingLinkingInfo; firebaseAuthenticator.clearTemporaryCredentials(); return }
        state = .authenticating("Signing in..."); lastError = nil
        do { let r = try await Auth.auth().signIn(with: cred); let u = User(firebaseUser: r.user); print("AuthService: Merge OK for \(u.uid)."); firebaseAuthenticator.clearTemporaryCredentials(); emailForLinking = nil; if !u.isAnonymous { try? secureStorage.saveLastUserID(u.uid) }; state = .signedIn(u) }
        catch { print("AuthService Error: Merge sign-in failed: \(error)"); lastError = AuthError.makeFirebaseAuthError(error); state = .signedOut; firebaseAuthenticator.clearTemporaryCredentials(); emailForLinking = nil }
    }

    public func cancelPendingAction() {
        print("AuthService: cancelPendingAction."); guard state.isPendingResolution else { print("AuthService: Cancel called but state not pending."); return }
        print("AuthService: User cancelled pending action."); state = .signedOut; lastError = nil; firebaseAuthenticator.clearTemporaryCredentials(); emailForLinking = nil
    }

    // MARK: - Private Helper Methods (@MainActor)

    private func resetForNewSignInAttempt() { print("Resetting."); firebaseAuthenticator.clearTemporaryCredentials(); emailForLinking = nil; lastError = nil }
    private func clearLocalUserData() { try? secureStorage.clearLastUserID(); firebaseAuthenticator.clearTemporaryCredentials(); emailForLinking = nil; lastError = nil; print("Cleared local data.") }
    private func performBiometricAuthentication(reason: String) async throws { try await withCheckedThrowingContinuation { c in biometricAuthenticator.authenticate(reason: reason) { r in switch r { case .success: c.resume(returning: ()); case .failure(let e): c.resume(throwing: e) } } } }

    private func completeSuccessfulSignIn(user: User) async {
        print("Completing sign-in for \(user.uid).")
        if let pCred = firebaseAuthenticator.pendingCredentialForLinking {
            print("Attempting link..."); do { try await performAccountLink(loggedInUser: user, pendingCredential: pCred); print("Link OK.") }
            catch let e as AuthError { print("Link fail: \(e)"); lastError = e; state = .signedOut; clearLocalUserData() }
            catch { print("Link fail unexpected: \(error)"); lastError = .accountLinkingError("Unexpected: \(error.localizedDescription)"); state = .signedOut; clearLocalUserData() }
        } else {
            print("Standard success/merge."); if firebaseAuthenticator.existingCredentialForMergeConflict != nil { firebaseAuthenticator.clearTemporaryCredentials(); emailForLinking = nil }; if !user.isAnonymous { try? secureStorage.saveLastUserID(user.uid) }; if state != .signedIn(user) { state = .signedIn(user) }
        }
    }

    // --- MODIFIED FUNCTION (Using email from error case) ---
    private func handleSignInAuthError(_ error: AuthError) async {
        print("AuthService: Handling AuthError: \(error.localizedDescription)")
        lastError = error
        switch error {
            // --- Use email from associated value ---
        case .accountLinkingRequired(let email):
            // Ensure credential is still stored for the actual linking step
            guard firebaseAuthenticator.pendingCredentialForLinking != nil else {
                print("AuthService Error: Account linking required but pending credential missing.")
                state = .signedOut; clearLocalUserData(); lastError = .missingLinkingInfo
                return
            }
            self.emailForLinking = email // Store email from the error
            do {
                // Fetch methods using the email from the error
                let methods = try await Auth.auth().fetchSignInMethods(forEmail: email)
                print("AuthService: Setting state to .requiresAccountLinking for \(email)")
                state = .requiresAccountLinking(email: email, existingProviders: methods.sorted())
            } catch let fetchError {
                print("AuthService Error: Fetching sign-in methods failed for \(email): \(fetchError.localizedDescription)")
                state = .signedOut // Fallback
                clearLocalUserData()
                lastError = AuthError.makeFirebaseAuthError(fetchError)
            }
            // --- End Modified Case ---

        case .mergeConflictRequired:
            guard firebaseAuthenticator.existingCredentialForMergeConflict != nil else { state = .signedOut; clearLocalUserData(); lastError = .missingLinkingInfo; return }; state = .requiresMergeConflictResolution
        case .cancelled:
            if !state.isPendingResolution { state = .signedOut; clearLocalUserData() } else { print("AuthService: Cancelled in pending state.") }
        case .unknown, .configurationError, .keychainError, .biometricsNotAvailable, .biometricsFailed, .firebaseUIError, .firebaseAuthError, .accountLinkingError, .mergeConflictError, .missingLinkingInfo:
            state = .signedOut; clearLocalUserData() // Reset on other errors
        }
    }
    // --- END MODIFIED FUNCTION ---

    private func handleSignInGenericError(_ error: Error) { print("AuthService: Handling Generic Error: \(error.localizedDescription)"); lastError = AuthError.makeFirebaseAuthError(error); state = .signedOut; clearLocalUserData() }

    private func performAccountLink(loggedInUser: User, pendingCredential: AuthCredential) async throws {
        guard let fbUser = Auth.auth().currentUser, fbUser.uid == loggedInUser.uid else { print("Auth Error: Link user mismatch."); firebaseAuthenticator.clearTemporaryCredentials(); throw AuthError.accountLinkingError("User mismatch.") }
        state = .authenticating("Linking..."); lastError = nil
        do { let r = try await fbUser.link(with: pendingCredential); let u = User(firebaseUser: r.user); print("Link OK!"); state = .signedIn(u); firebaseAuthenticator.clearTemporaryCredentials(); emailForLinking = nil; lastError = nil; if !u.isAnonymous { try? secureStorage.saveLastUserID(u.uid) } }
        catch { print("Link Fail: \(error)"); firebaseAuthenticator.clearTemporaryCredentials(); emailForLinking = nil; let e = error as NSError; if e.domain == AuthErrorDomain && e.code == AuthErrorCode.credentialAlreadyInUse.rawValue { throw AuthError.accountLinkingError("Already linked.") } else { throw AuthError.accountLinkingError("Link failed: \(error.localizedDescription)") } }
    }

    private func handleAuthStateChange(firebaseUser: FirebaseAuth.User?) {
        if let fbUser = firebaseUser {
            let u = User(firebaseUser: fbUser)
            print("Listener: User PRESENT (\(u.uid)) State: \(state)")
            if state.isPendingResolution || state == .authenticating(nil) {
                print(" Ignoring update.")
                return
            }
            if case .signedIn(let c) = state, c.uid == u.uid {
                print(" State correct. Check bio.")
                checkBiometricsRequirement(for: u)
                return
            }
            print(" User changed/state differs. Check bio.")
            checkBiometricsRequirement(for: u)
        } else {
            print("Listener: User ABSENT State: \(state)")
            if state != .signedOut {
                print(" Set state signedOut.")
                clearLocalUserData()
                state = .signedOut
            }
        }
    }

    private func checkBiometricsRequirement(for user: User) {
        guard !user.isAnonymous else { print(" Skip bio for anon."); if state != .signedIn(user) { state = .signedIn(user) }; return }; let l = secureStorage.getLastUserID(); let b = biometricAuthenticator.isBiometricsAvailable; if l == user.uid && b { if !(state == .signedIn(user)) { state = .requiresBiometrics } } else { if state != .signedIn(user) { state = .signedIn(user) }; if l != user.uid || !b { try? secureStorage.saveLastUserID(user.uid) } }
    }
} // <-- End AuthService
