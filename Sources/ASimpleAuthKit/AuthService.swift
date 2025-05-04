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

    // Dependencies (now protocols where possible)
    private let config: AuthConfig
    private let firebaseAuthenticator: FirebaseAuthenticatorProtocol
    private let biometricAuthenticator: BiometricAuthenticatorProtocol
    private let secureStorage: SecureStorageProtocol

    // Internal State
    private var authStateHandle: AuthStateDidChangeListenerHandle?
    private var cancellables = Set<AnyCancellable>()
    private var emailForLinking: String? // Stores email during linking flow
    private let isTestMode: Bool // <<< Added for testing

    // Designated Initializer (Internal - for DI and testing)
    internal init(
        config: AuthConfig,
        secureStorage: SecureStorageProtocol,
        firebaseAuthenticator: FirebaseAuthenticatorProtocol,
        biometricAuthenticator: BiometricAuthenticatorProtocol,
        isTestMode: Bool = false // <<< Added parameter with default
    ) {
        self.config = config
        self.secureStorage = secureStorage
        self.firebaseAuthenticator = firebaseAuthenticator
        self.biometricAuthenticator = biometricAuthenticator
        self.isTestMode = isTestMode // <<< Assign parameter
        print("AuthService (Designated Init): Initializing with injected dependencies. Test Mode: \(isTestMode)")

        // Setup listener using FirebaseAuth directly
        self.authStateHandle = Auth.auth().addStateDidChangeListener { [weak self] (_, user) in
            Task { @MainActor [weak self] in
                    guard let strongSelf = self, !strongSelf.isTestMode else {
                        // print("AuthService Listener: Skipping handleAuthStateChange in test mode.") // Keep logs minimal
                        return
                    }
                    strongSelf.handleAuthStateChange(firebaseUser: user)
            }
        }

        // Initial state check using FirebaseAuth directly
        Task { @MainActor [weak self] in
             guard let strongSelf = self, !strongSelf.isTestMode else {
                 // print("AuthService Initial Check: Skipping initial state check in test mode.") // Keep logs minimal
                 return
             }
            strongSelf.handleAuthStateChange(firebaseUser: Auth.auth().currentUser)
        }
        print("AuthService (Designated Init): Init complete, listener added.")
    }

    // Convenience Initializer (Public - for production use)
    public convenience init(config: AuthConfig) {
        let storage = KeychainStorage(accessGroup: config.keychainAccessGroup)
        let bioAuth = BiometricAuthenticator()
        let fireAuth = FirebaseAuthenticator(config: config, secureStorage: storage)
        self.init(
            config: config,
            secureStorage: storage,
            firebaseAuthenticator: fireAuth,
            biometricAuthenticator: bioAuth
        )
        print("AuthService (Convenience Init): Created concrete dependencies.")
    }

    deinit {
        print("AuthService: Deinit started.")
        Task { @MainActor [weak self] in
            guard let strongSelf = self else { return }
            if let handle = strongSelf.authStateHandle {
                print("AuthService: Removing Firebase Auth state listener on MainActor.")
                Auth.auth().removeStateDidChangeListener(handle)
                strongSelf.authStateHandle = nil
            } else {
                print("AuthService: No listener handle found during deinit task.")
            }
        }
        print("AuthService: Deinit finished scheduling cleanup task.")
    }


    // MARK: - Public API (@MainActor)
    public func signIn(from viewController: UIViewController) async {
        print("AuthService: signIn requested. State: \(state)")
        guard state.allowsSignInAttempt else {
            print("AuthService: Sign-in not allowed for state \(state).")
            return
        }

        if state == .signedOut {
             resetForNewSignInAttempt()
         } else if state.isPendingResolution || state == .requiresBiometrics {
             print("AuthService: Sign-in attempt from pending/bio state. Clearing error only.")
             lastError = nil
         }

        let msg = state.isPendingResolution ? "Signing in..." : "Starting sign in..."
        state = .authenticating(msg)
        // Ensure error is cleared at the start of the attempt (moved from resetForNewSignInAttempt)
        if !state.isPendingResolution { // Don't clear error if resolving pending state
             lastError = nil
        }

        var dismiss = true

        do {
            let user = try await firebaseAuthenticator.presentSignInUI(from: viewController)
            await completeSuccessfulSignIn(user: user)
            // Error cleared within successful completion paths now
        } catch let e as AuthError {
            await handleSignInAuthError(e) // Sets lastError internally
            // Don't dismiss if pending or cancelled (user might want to retry)
            if state.isPendingResolution || e == .cancelled {
                dismiss = false
            }
        } catch {
            handleSignInGenericError(error) // Sets lastError internally
        }

        // Re-evaluate dismissal based on final state AFTER potential error handling
        if state.isPendingResolution || state == .requiresBiometrics { // Keep UI for bio state too
            dismiss = false
        }

        if dismiss {
            print("AuthService: Dismissing UI.")
            viewController.dismiss(animated: true)
        } else {
            print("AuthService: UI remains for state: \(state).")
        }
    }

    public func signOut() {
        print("AuthService: signOut requested.")
        do {
            try Auth.auth().signOut()
            clearLocalUserData()
            lastError = nil // Clear error on success
            print("AuthService: Sign out OK.")
            if isTestMode {
                state = .signedOut
                print("AuthService: (Test Mode) Manually setting state to signedOut.")
            }
        } catch {
            print("AuthService: Sign out failed: \(error)")
            lastError = AuthError.makeFirebaseAuthError(error)
            clearLocalUserData() // Still clear local data on failure
            state = .signedOut // Ensure state is signedOut on failure too
        }
    }

    public func authenticateWithBiometrics(reason: String = "Sign in to your account") async {
        print("AuthService: Bio requested. State: \(state)")
        guard state == .requiresBiometrics else {
            print("Auth Warning: Bio requested but not required. State is \(state)")
            return
        }
        guard let currentFirebaseUser = Auth.auth().currentUser else {
            print("Auth Error: Bio required but no Firebase user found. Resetting.")
            lastError = .configurationError("Biometrics required but no logged-in user found.")
            clearLocalUserData()
            state = .signedOut
            return
        }
        let uid = currentFirebaseUser.uid

        state = .authenticating(biometricAuthenticator.biometryTypeString)
        lastError = nil
        do {
            try await performBiometricAuthentication(reason: reason)
            print("AuthService: Bio successful.")
            // Re-verify user hasn't changed unexpectedly
            if let refreshedUser = Auth.auth().currentUser, refreshedUser.uid == uid {
                let user = AuthUser(firebaseUser: refreshedUser)
                // Save user ID *after* successful bio auth for non-anonymous user
                // This reinforces the link between the device auth and the user ID.
                if !user.isAnonymous {
                     try? secureStorage.saveLastUserID(user.uid)
                     print("Saved last user ID post-successful bio auth.")
                 }
                state = .signedIn(user)
                lastError = nil // Clear error on success
                print("AuthService: State -> signedIn.")
            } else {
                print("Auth Warning: User changed during bio auth or became nil. Resetting.")
                lastError = .unknown
                state = .signedOut
                clearLocalUserData()
            }
        } catch let e as AuthError {
            print("AuthService: Bio failed: \(e.localizedDescription)")
            self.lastError = e
            self.state = .requiresBiometrics // Stay in requiresBiometrics state
        } catch {
            print("AuthService: Unexpected bio error: \(error)")
            self.lastError = .unknown
            self.state = .requiresBiometrics // Stay in requiresBiometrics state
        }
    }

    public func proceedWithMergeConflictResolution() async {
        print("AuthService: proceedWithMerge. State: \(state)")
        guard state == .requiresMergeConflictResolution else {
            print("Auth Warning: Not in merge state.")
            return
        }
        guard let cred = firebaseAuthenticator.existingCredentialForMergeConflict else {
            print("Auth Error: Missing merge cred.")
            state = .signedOut
            lastError = .missingLinkingInfo
            firebaseAuthenticator.clearTemporaryCredentials()
            return
        }

        state = .authenticating("Signing in...")
        lastError = nil
        do {
            let r = try await Auth.auth().signIn(with: cred)
            let u = AuthUser(firebaseUser: r.user)
            print("AuthService: Merge OK for \(u.uid).")
            firebaseAuthenticator.clearTemporaryCredentials() // Clear *after* success
            emailForLinking = nil
            // Check biometrics before setting final state
            checkBiometricsRequirement(for: u) // Sets state to signedIn or requiresBiometrics
            lastError = nil // Clear error on success
        } catch {
            print("AuthService Error: Merge sign-in failed: \(error)")
            lastError = AuthError.makeFirebaseAuthError(error)
            state = .signedOut
            firebaseAuthenticator.clearTemporaryCredentials() // Clear on failure too
            emailForLinking = nil
        }
    }

    public func cancelPendingAction() {
        print("AuthService: cancelPendingAction.")
        guard state.isPendingResolution else {
            print("AuthService: Cancel called but state not pending.")
            return
        }
        print("AuthService: User cancelled pending action: \(state)")
        state = .signedOut
        lastError = nil // Clear error on cancel
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
    }

    // MARK: - Private Helper Methods (@MainActor)

    private func resetForNewSignInAttempt() {
        print("Resetting for new sign-in attempt.")
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
        // Don't clear lastError here, cleared at start of signIn if needed
        // Don't clear secure storage here
    }

    private func clearLocalUserData() {
        try? secureStorage.clearLastUserID()
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
        // Don't automatically clear lastError here
        print("Cleared local user data (Keychain, Temp Creds, Email Link).")
    }

    private func performBiometricAuthentication(reason: String) async throws {
        try await withCheckedThrowingContinuation { c in
            biometricAuthenticator.authenticate(reason: reason) { r in
                switch r {
                case .success: c.resume(returning: ())
                case .failure(let e): c.resume(throwing: e)
                }
            }
        }
    }

    // --- COMPLETE SUCCESSFUL SIGN IN ---
    private func completeSuccessfulSignIn(user: AuthUser) async {
        print("Completing sign-in for \(user.uid). Current State: \(state)")

        if let pCred = firebaseAuthenticator.pendingCredentialForLinking {
            // --- Account Linking Path ---
            print("Attempting account link...")
            do {
                // Perform link, which internally calls checkBiometricsRequirement
                try await performAccountLink(loggedInUser: user, pendingCredential: pCred)
                print("Link successful.")
                lastError = nil // Ensure error cleared on link success
            }
            catch let e as AuthError {
                print("Link failed: \(e.localizedDescription)")
                lastError = e // Set specific link error
                state = .signedOut // Revert to signedOut on link failure
                clearLocalUserData()
            } catch { // Catch generic link errors
                print("Link failed unexpectedly: \(error)")
                lastError = .accountLinkingError("Unexpected link error: \(error.localizedDescription)")
                state = .signedOut
                clearLocalUserData()
            }
        } else {
            // --- Standard Sign-in / Post-Merge Path ---
            print("Standard sign-in success or post-merge sign-in for user \(user.uid).")
            // Clear merge conflict credential if it existed
            if firebaseAuthenticator.existingCredentialForMergeConflict != nil {
                firebaseAuthenticator.clearTemporaryCredentials()
                emailForLinking = nil
                print("Cleared merge conflict credentials post-successful sign-in.")
            }

            // Check biometrics *before* setting final state
            // This function now sets the state (.signedIn or .requiresBiometrics)
            // AND handles saving the user ID if appropriate.
            checkBiometricsRequirement(for: user)

            // <<< FIX: Removed redundant save call here >>>
            // if state == .signedIn(user) && !user.isAnonymous {
            //      try? secureStorage.saveLastUserID(user.uid) // << REMOVED
            //      print("Saved last user ID for non-anonymous user.") // << REMOVED
            // }

            lastError = nil // Clear any previous error on success path
        }
    }
    // --- END COMPLETE SUCCESSFUL SIGN IN ---


    private func handleSignInAuthError(_ error: AuthError) async {
        print("AuthService: Handling AuthError: \(error.localizedDescription)")
        lastError = error // Set the error state first

        switch error {
        case .accountLinkingRequired(let email):
            guard firebaseAuthenticator.pendingCredentialForLinking != nil else {
                print("AuthService Error: Account linking required but pending credential missing.")
                state = .signedOut
                lastError = .missingLinkingInfo // Overwrite previous error
                firebaseAuthenticator.clearTemporaryCredentials() // Clear just in case
                return
            }
            self.emailForLinking = email // Store email from the error

            do {
                let methods = try await Auth.auth().fetchSignInMethods(forEmail: email)
                print("AuthService: Setting state to .requiresAccountLinking for \(email)")
                state = .requiresAccountLinking(email: email, existingProviders: methods.sorted())
                // Keep lastError as the original .accountLinkingRequired
            } catch let fetchError {
                print("AuthService Error: Fetching sign-in methods failed for \(email): \(fetchError.localizedDescription)")
                state = .signedOut // Fallback if fetch fails
                lastError = AuthError.makeFirebaseAuthError(fetchError) // Update error to fetch error
                firebaseAuthenticator.clearTemporaryCredentials() // Clear creds if fetch fails
                emailForLinking = nil
            }

        case .mergeConflictRequired:
            guard firebaseAuthenticator.existingCredentialForMergeConflict != nil else {
                print("AuthService Error: Merge conflict required but existing credential missing.")
                state = .signedOut
                lastError = .missingLinkingInfo
                firebaseAuthenticator.clearTemporaryCredentials()
                return
            }
            state = .requiresMergeConflictResolution
            // Keep lastError as the original .mergeConflictRequired

        case .cancelled:
            if !state.isPendingResolution {
                state = .signedOut
                 firebaseAuthenticator.clearTemporaryCredentials() // Clear creds on cancel only if not pending
                 emailForLinking = nil
            } else {
                print("AuthService: Cancelled while in pending state (\(state)). State remains.")
            }
            // Keep lastError as .cancelled

        // Default case for other errors: revert to signedOut
        default:
            state = .signedOut
            firebaseAuthenticator.clearTemporaryCredentials() // Clear creds on general failure
            emailForLinking = nil
            // Keep the specific lastError that was set at the beginning
        }
    }

    private func handleSignInGenericError(_ error: Error) {
        print("AuthService: Handling Generic Error: \(error.localizedDescription)")
        lastError = AuthError.makeFirebaseAuthError(error)
        state = .signedOut
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
    }

    // --- PERFORM ACCOUNT LINK ---
    private func performAccountLink(loggedInUser: AuthUser, pendingCredential: AuthCredential) async throws {
        guard let fbUser = Auth.auth().currentUser, fbUser.uid == loggedInUser.uid else {
            print("Auth Error: Link user mismatch.")
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
            state = .signedOut
            lastError = .accountLinkingError("User mismatch during linking.")
            throw AuthError.accountLinkingError("User mismatch during linking.")
        }
        state = .authenticating("Linking account...")
        lastError = nil

        do {
            let r = try await fbUser.link(with: pendingCredential)
            let updatedUser = AuthUser(firebaseUser: r.user)
            print("Link successful!")
            firebaseAuthenticator.clearTemporaryCredentials() // Clear creds after successful link
            emailForLinking = nil
            lastError = nil

            // Check biometrics AFTER successful linking before setting final state
            // This handles state update and saving UID if needed.
             checkBiometricsRequirement(for: updatedUser)

             // <<< FIX: Removed redundant save call here >>>
             // if state == .signedIn(updatedUser) && !updatedUser.isAnonymous {
             //     try? secureStorage.saveLastUserID(updatedUser.uid) // << REMOVED
             //     print("Saved last user ID after successful link.") // << REMOVED
             // }

        } catch {
            print("Link failed: \(error.localizedDescription)")
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
            let nsError = error as NSError
            let specificError: AuthError
            if nsError.domain == AuthErrorDomain && nsError.code == AuthErrorCode.credentialAlreadyInUse.rawValue {
                specificError = AuthError.accountLinkingError("This sign-in method is already linked to another account.")
            } else {
                specificError = AuthError.accountLinkingError("Failed to link account: \(error.localizedDescription)")
            }
            lastError = specificError
            state = .signedOut // Revert state on failure
            throw specificError // Rethrow the specific error
        }
    }
     // --- END PERFORM ACCOUNT LINK ---


    private func handleAuthStateChange(firebaseUser: FirebaseAuth.User?) {
         guard !isTestMode else { return } // Extra safety

        if let fbUser = firebaseUser {
            let currentUser = AuthUser(firebaseUser: fbUser)
            print("AuthService Listener: User PRESENT (\(currentUser.uid)). Current State: \(state)")

            if state.isPendingResolution || (state.isAuthenticating && state != .requiresBiometrics) {
                print("AuthService Listener: Ignoring update due to pending/authenticating state.")
                return
            }

            if case .signedIn(let existingUser) = state, existingUser.uid == currentUser.uid {
                 print("AuthService Listener: State already signedIn with correct user. Re-checking biometrics.")
                 checkBiometricsRequirement(for: currentUser)
                 return
             }
            if state == .requiresBiometrics {
                print("AuthService Listener: State is requiresBiometrics. Re-checking biometrics.")
                checkBiometricsRequirement(for: currentUser) // Re-check might transition to signedIn if needed
                return
            }

            print("AuthService Listener: User changed or state was out of sync. Updating state based on listener.")
             checkBiometricsRequirement(for: currentUser)

        } else {
             print("AuthService Listener: User ABSENT. Current AuthService State: \(state)")
             if state != .signedOut && !state.isAuthenticating {
                 print("AuthService Listener: Setting state to signedOut.")
                 clearLocalUserData()
                 state = .signedOut
                 lastError = nil // Clear error on listener-driven sign-out
             } else {
                 print("AuthService Listener: State already signedOut or currently authenticating, no state change needed.")
             }
         }
    }

    // --- Biometrics Check (Handles state setting and saving) ---
     private func checkBiometricsRequirement(for user: AuthUser) {
         guard !user.isAnonymous else {
             print("AuthService Biometrics Check: Skip bio for anonymous user.")
             if state != .signedIn(user) { state = .signedIn(user) }
             return
         }

         let lastUserID = secureStorage.getLastUserID()
         let bioAvailable = biometricAuthenticator.isBiometricsAvailable
         print("AuthService Biometrics Check: User: \(user.uid), Stored: \(lastUserID ?? "nil"), Bio Available: \(bioAvailable)")

         // Condition: Require Biometrics?
         if bioAvailable && lastUserID == user.uid {
             if state != .requiresBiometrics {
                 state = .requiresBiometrics
                 print("AuthService Biometrics Check: State -> requiresBiometrics")
             } // else: State already correct, do nothing
         }
         // Condition: Simple Signed In
         else {
             if state != .signedIn(user) {
                 state = .signedIn(user)
                 print("AuthService Biometrics Check: State -> signedIn (Non-anonymous, Bio not required/matched)")
             } // else: State already correct, do nothing

             // Save User ID ONLY if we are in the simple signedIn state
             // (meaning bio wasn't required OR user changed OR bio became unavailable)
             // This prevents saving again after successful biometric auth.
             if state == .signedIn(user) { // Check state *after* potential update above
                  if lastUserID != user.uid || !bioAvailable {
                       try? secureStorage.saveLastUserID(user.uid)
                       print("AuthService Biometrics Check: Saved last user ID (\(user.uid)) as biometrics are not currently required/matched.")
                   }
              }
         }
     }
     // --- END Biometrics Check ---

    // MARK: - Test Helpers
    #if DEBUG
    @MainActor
    internal func forceStateForTesting(_ state: AuthState) {
        guard isTestMode else {
            print("AuthService: forceStateForTesting can only be used in test mode.")
            return
        }
        print("AuthService (Test Mode): Forcing state to \(state)")
        self.state = state
    }
    #endif
}
