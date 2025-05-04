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
        // NOTE: This still relies on the global Auth.auth() singleton
        self.authStateHandle = Auth.auth().addStateDidChangeListener { [weak self] (_, user) in
            Task {
                @MainActor [weak self] in
                    // <<< Added guard for test mode
                    guard let strongSelf = self, !strongSelf.isTestMode else {
                        print("AuthService Listener: Skipping handleAuthStateChange in test mode.")
                        return
                    }
                    strongSelf.handleAuthStateChange(firebaseUser: user)
            }
        }

        // Initial state check using FirebaseAuth directly
        Task { @MainActor [weak self] in
             // <<< Added guard for test mode
             guard let strongSelf = self, !strongSelf.isTestMode else {
                 print("AuthService Initial Check: Skipping initial state check in test mode.")
                 return
             }
            strongSelf.handleAuthStateChange(firebaseUser: Auth.auth().currentUser)
        }
        print("AuthService (Designated Init): Init complete, listener added.")
    }

    // Convenience Initializer (Public - for production use)
    public convenience init(config: AuthConfig) {
        // Create concrete dependencies
        let storage = KeychainStorage(accessGroup: config.keychainAccessGroup) // Uses convenience init of KeychainStorage
        let bioAuth = BiometricAuthenticator()
        // FirebaseAuthenticator needs config and storage
        let fireAuth = FirebaseAuthenticator(config: config, secureStorage: storage)

        // Call the designated initializer with concrete types
        // Production always uses isTestMode: false (default)
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
        guard state.allowsSignInAttempt else {
            print("AuthService: Sign-in not allowed for state \(state).") // More informative log
            return
        }

        // Reset state only if truly starting fresh
        if state == .signedOut { // Only reset from fully signed out
             resetForNewSignInAttempt()
         } else if state.isPendingResolution || state == .requiresBiometrics {
             // Don't fully reset if resolving linking/merge or re-authenticating from bio required
             print("AuthService: Sign-in attempt from pending/bio state. Clearing error only.")
             lastError = nil // Clear previous error for the new attempt
         }

        let msg = state.isPendingResolution ? "Signing in..." : "Starting sign in..."
        state = .authenticating(msg)
        lastError = nil // <<< Ensure error is cleared at the start
        var dismiss = true

        do {
            let user = try await firebaseAuthenticator.presentSignInUI(from: viewController)
            await completeSuccessfulSignIn(user: user)
            lastError = nil // Clear error on full success path completion
        } catch let e as AuthError {
            await handleSignInAuthError(e) // Sets lastError internally
            if state.isPendingResolution || e == .cancelled {
                dismiss = false
            }
        } catch {
            handleSignInGenericError(error) // Sets lastError internally
        } // Catch generic error

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
            // Note: This still relies on the global Auth singleton
            // If testing in isolation, this might need mocking too, but
            // for now, we assume the listener handles the state change (unless in test mode)
            try Auth.auth().signOut()
            clearLocalUserData() // <<< Clear local data AFTER successful Firebase sign out
            lastError = nil // <<< Clear error on success
            print("AuthService: Sign out OK.")
            // State change should be handled by the listener if not in test mode
            // If in test mode, the listener is off, so we manually set state
            if isTestMode {
                state = .signedOut
                print("AuthService: (Test Mode) Manually setting state to signedOut.")
            }

        } catch {
            print("AuthService: Sign out failed: \(error)")
            lastError = AuthError.makeFirebaseAuthError(error) // Set error
            // Ensure clean state even on failure
            clearLocalUserData()
            state = .signedOut // <<< Ensure state is signedOut on failure too
        }
    }

    public func authenticateWithBiometrics(reason: String = "Sign in to your account") async {
        print("AuthService: Bio requested. State: \(state)")
        guard state == .requiresBiometrics else {
            print("Auth Warning: Bio requested but not required. State is \(state)")
            return
        }
        // We need the *current* user associated with requiresBiometrics state.
        // This info isn't directly stored in the state enum. Let's try getting it from Auth
        guard let currentFirebaseUser = Auth.auth().currentUser else {
            print("Auth Error: Bio required but no Firebase user found. Resetting.")
            lastError = .configurationError("Biometrics required but no logged-in user found.") // <<< Set error
            clearLocalUserData()
            state = .signedOut
            return
        }
        let uid = currentFirebaseUser.uid

        state = .authenticating(biometricAuthenticator.biometryTypeString)
        lastError = nil // <<< Clear error at start
        do {
            try await performBiometricAuthentication(reason: reason)
            print("AuthService: Bio successful.")
            // Re-verify user hasn't changed unexpectedly during async operation
            if let refreshedUser = Auth.auth().currentUser, refreshedUser.uid == uid {
                let user = AuthUser(firebaseUser: refreshedUser)
                if !user.isAnonymous {
                     // Save user ID *after* successful bio auth for non-anonymous user
                     // This reinforces the link between the device auth and the user ID.
                     try? secureStorage.saveLastUserID(user.uid)
                 }
                state = .signedIn(user)
                lastError = nil // Clear error on success
                print("AuthService: State -> signedIn.")

            } else {
                print("Auth Warning: User changed during bio auth or became nil. Resetting.")
                lastError = .unknown // Set error
                state = .signedOut
                clearLocalUserData()
            }

        } catch let e as AuthError {
            print("AuthService: Bio failed: \(e.localizedDescription)")
            self.lastError = e // Set error
            // Stay in requiresBiometrics state on failure
            self.state = .requiresBiometrics

        } catch {
            print("AuthService: Unexpected bio error: \(error)")
            self.lastError = .unknown // Set error
            // Stay in requiresBiometrics state on failure
            self.state = .requiresBiometrics
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
            lastError = .missingLinkingInfo // <<< Set error
            firebaseAuthenticator.clearTemporaryCredentials()
            return
        }

        state = .authenticating("Signing in...")
        lastError = nil // <<< Clear error at start
        do {
            // Note: Still relies on global Auth singleton
            let r = try await Auth.auth().signIn(with: cred)
            let u = AuthUser(firebaseUser: r.user)
            print("AuthService: Merge OK for \(u.uid).")
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
            if !u.isAnonymous {
                try? secureStorage.saveLastUserID(u.uid)
            }
            state = .signedIn(u)
            lastError = nil // Clear error on success
        } catch {
            print("AuthService Error: Merge sign-in failed: \(error)")
            lastError = AuthError.makeFirebaseAuthError(error) // <<< Set error
            state = .signedOut
            firebaseAuthenticator.clearTemporaryCredentials()
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
        lastError = nil // <<< Clear error on cancel
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
    }

    // MARK: - Private Helper Methods (@MainActor)

    private func resetForNewSignInAttempt() {
        print("Resetting for new sign-in attempt.")
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
        lastError = nil // <<< Clear error on reset
        // Don't clear secure storage here, only on explicit sign-out
    }

    private func clearLocalUserData() {
        try? secureStorage.clearLastUserID()
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
        // lastError = nil // <<< REMOVED: Don't clear error here automatically
        print("Cleared local user data (Keychain, Temp Creds, Email Link).")
    }

    private func performBiometricAuthentication(reason: String) async throws {
        try await withCheckedThrowingContinuation {
            c in biometricAuthenticator.authenticate(reason: reason) {
                r in switch r {
                    case .success: c.resume(returning: ())
                    case .failure(let e): c.resume(throwing: e)
                }
            }
        }
    }

    private func completeSuccessfulSignIn(user: AuthUser) async {
        print("Completing sign-in for \(user.uid). Current State: \(state)")
        // This function runs *after* presentSignInUI returns successfully,
        // but *before* the state might be updated by the listener (if not in test mode).
        // The state is likely still .authenticating(...) here.

        if let pCred = firebaseAuthenticator.pendingCredentialForLinking {
            print("Attempting account link...")
            do {
                try await performAccountLink(loggedInUser: user, pendingCredential: pCred)
                print("Link successful.")
                // State is set to signedIn within performAccountLink
                lastError = nil // Ensure error cleared on success
            }
            catch let e as AuthError {
                print("Link failed: \(e.localizedDescription)")
                lastError = e // Set error
                state = .signedOut // Revert to signedOut on link failure
                clearLocalUserData()
            } catch {
                print("Link failed unexpectedly: \(error)")
                lastError = .accountLinkingError("Unexpected: \(error.localizedDescription)") // Set error
                state = .signedOut // Revert to signedOut on link failure
                clearLocalUserData()
            }
        } else {
            // Handle standard sign-in or post-merge sign-in
            print("Standard sign-in success or post-merge sign-in for user \(user.uid).")
            // Clear merge conflict credential if it existed (it would have been used to sign in just before this)
            if firebaseAuthenticator.existingCredentialForMergeConflict != nil {
                firebaseAuthenticator.clearTemporaryCredentials()
                emailForLinking = nil // Should be nil anyway, but clear for safety
                print("Cleared merge conflict credentials post-successful sign-in.")
            }

            // Check biometrics BEFORE setting final signedIn state
             checkBiometricsRequirement(for: user) // This function now sets the state (.signedIn or .requiresBiometrics)

            // Save user ID after successful non-anonymous sign-in *if state didn't become requiresBiometrics*
            // If state *is* requiresBiometrics, saving happens after successful bio auth.
            if state == .signedIn(user) && !user.isAnonymous {
                 try? secureStorage.saveLastUserID(user.uid)
                 print("Saved last user ID for non-anonymous user.")
             }

            lastError = nil // Clear any previous error on success path
        }
    }

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

            // Attempt to fetch sign-in methods
            // NOTE: Still relies on global Auth singleton
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
                lastError = .missingLinkingInfo // Overwrite previous error
                firebaseAuthenticator.clearTemporaryCredentials() // Clear just in case
                return
            }
            // Credential exists, set the state
            state = .requiresMergeConflictResolution
            // Keep lastError as the original .mergeConflictRequired

        case .cancelled:
            // If we were in a pending state, stay there (UI likely still visible).
            // Otherwise, revert to signedOut.
            if !state.isPendingResolution {
                state = .signedOut
                 firebaseAuthenticator.clearTemporaryCredentials() // Clear creds on cancel only if not pending
                 emailForLinking = nil
            } else {
                print("AuthService: Cancelled while in pending state (\(state)). State remains.")
            }
            // Keep lastError as .cancelled

        // Default case for other errors: revert to signedOut
        case .unknown, .configurationError, .keychainError, .biometricsNotAvailable, .biometricsFailed, .firebaseUIError, .firebaseAuthError, .accountLinkingError, .mergeConflictError, .missingLinkingInfo:
            state = .signedOut
            firebaseAuthenticator.clearTemporaryCredentials() // Clear creds on general failure
            emailForLinking = nil
            // Keep the specific lastError that was set at the beginning of the function
        }
    }

    private func handleSignInGenericError(_ error: Error) {
        print("AuthService: Handling Generic Error: \(error.localizedDescription)")
        lastError = AuthError.makeFirebaseAuthError(error) // Set error
        state = .signedOut
        firebaseAuthenticator.clearTemporaryCredentials() // Clear creds on generic failure
        emailForLinking = nil
    }

    private func performAccountLink(loggedInUser: AuthUser, pendingCredential: AuthCredential) async throws {
        guard let fbUser = Auth.auth().currentUser, fbUser.uid == loggedInUser.uid else {
            print("Auth Error: Link user mismatch.")
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
            // Set state and error before throwing
            state = .signedOut
            lastError = .accountLinkingError("User mismatch during linking.")
            throw AuthError.accountLinkingError("User mismatch during linking.")
        }
        state = .authenticating("Linking account...") // Update state message
        lastError = nil // Clear error before attempting link

        do {
            let r = try await fbUser.link(with: pendingCredential)
            let updatedUser = AuthUser(firebaseUser: r.user)
            print("Link successful!")
            firebaseAuthenticator.clearTemporaryCredentials() // Clear creds after successful link
            emailForLinking = nil
            lastError = nil // Ensure error is nil on success

            // Check biometrics AFTER successful linking before setting final state
             checkBiometricsRequirement(for: updatedUser) // This sets state (.signedIn or .requiresBiometrics)

             // Save user ID if state is .signedIn and user is not anonymous
             if state == .signedIn(updatedUser) && !updatedUser.isAnonymous {
                 try? secureStorage.saveLastUserID(updatedUser.uid)
                 print("Saved last user ID after successful link.")
             }

        } catch {
            print("Link failed: \(error.localizedDescription)")
            firebaseAuthenticator.clearTemporaryCredentials() // Clear creds on link failure
            emailForLinking = nil
            let nsError = error as NSError
            let specificError: AuthError
            if nsError.domain == AuthErrorDomain && nsError.code == AuthErrorCode.credentialAlreadyInUse.rawValue {
                specificError = AuthError.accountLinkingError("This sign-in method is already linked to another account.")
            } else {
                specificError = AuthError.accountLinkingError("Failed to link account: \(error.localizedDescription)")
            }
            lastError = specificError // Set error
            state = .signedOut // Revert state on failure
            throw specificError // Rethrow the specific error
        }
    }

    // --- Listener ---
    // NOTE: This function is NOT called if isTestMode is true
    private func handleAuthStateChange(firebaseUser: FirebaseAuth.User?) {
        if let fbUser = firebaseUser {
            let currentUser = AuthUser(firebaseUser: fbUser)
            print("AuthService Listener: User PRESENT (\(currentUser.uid)). Current AuthService State: \(state)")

            // Ignore listener updates if we are in a state that requires user interaction
            // or if we are actively authenticating (unless state is requiresBiometrics)
            if state.isPendingResolution || (state.isAuthenticating && state != .requiresBiometrics) {
                print("AuthService Listener: Ignoring update due to pending/authenticating state.")
                return
            }

            // If state is already signedIn with the same user, or requires biometrics for this user,
            // just ensure biometrics are checked, don't forcibly change state unless necessary.
            if case .signedIn(let existingUser) = state, existingUser.uid == currentUser.uid {
                 print("AuthService Listener: State already signedIn with correct user. Checking biometrics.")
                 checkBiometricsRequirement(for: currentUser) // Re-check biometrics
                 return
             }
            if state == .requiresBiometrics {
                // If requiresBiometrics, the user *should* match. If they don't, something is wrong.
                // Re-check biometrics to potentially transition to signedIn if needed (e.g., bio became unavailable)
                print("AuthService Listener: State is requiresBiometrics. Re-checking biometrics.")
                checkBiometricsRequirement(for: currentUser)
                return
            }

            // If we reach here, the user is present, but the state is something else
            // (e.g., signedOut, or signedIn with a *different* user).
            // The listener indicates the authoritative state is this new user.
            print("AuthService Listener: User changed or state was out of sync. Updating state based on listener.")
             checkBiometricsRequirement(for: currentUser) // Determine correct state (.signedIn or .requiresBiometrics)

        } else {
             // Firebase Auth says no user is signed in.
             print("AuthService Listener: User ABSENT. Current AuthService State: \(state)")
             // Only reset if the state wasn't already signedOut or if we weren't mid-authentication attempt
             if state != .signedOut && !state.isAuthenticating {
                 print("AuthService Listener: Setting state to signedOut.")
                 clearLocalUserData() // Clear local data when Firebase confirms sign-out
                 state = .signedOut
                 lastError = nil // Clear error on listener-driven sign-out
             } else {
                 print("AuthService Listener: State already signedOut or currently authenticating, no state change needed.")
             }
         }
    }

    // --- Biometrics Check ---
    // <<< REVISED LOGIC >>>
     private func checkBiometricsRequirement(for user: AuthUser) {
         guard !user.isAnonymous else {
             print("AuthService Biometrics Check: Skip bio for anonymous user.")
             // If state isn't already correctly signedIn, set it.
             if state != .signedIn(user) {
                 state = .signedIn(user)
                 print("AuthService Biometrics Check: State -> signedIn (Anonymous)")
             }
             return
         }

         let lastUserID = secureStorage.getLastUserID()
         let bioAvailable = biometricAuthenticator.isBiometricsAvailable

         print("AuthService Biometrics Check: User: \(user.uid), Stored: \(lastUserID ?? "nil"), Bio Available: \(bioAvailable)")

         // Condition for requiring biometrics:
         // 1. Biometrics are available on the device.
         // 2. The currently signed-in user matches the last successfully signed-in user ID stored locally.
         if bioAvailable && lastUserID == user.uid {
             // If the state isn't already requiresBiometrics, set it.
             if state != .requiresBiometrics {
                 state = .requiresBiometrics
                 print("AuthService Biometrics Check: State -> requiresBiometrics")
             } else {
                  print("AuthService Biometrics Check: State already requiresBiometrics.")
             }
         } else {
             // Condition for simple signedIn state:
             // Either biometrics aren't available, or the user doesn't match the stored ID (new user, or different user).
             // If the state isn't already signedIn with this user, set it.
             if state != .signedIn(user) {
                 state = .signedIn(user)
                 print("AuthService Biometrics Check: State -> signedIn (Non-anonymous, Bio not required/matched)")
             } else {
                 print("AuthService Biometrics Check: State already signedIn.")
             }

             // Save the user ID if biometrics are NOT required for this session.
             // This happens if:
             // a) Biometrics became unavailable.
             // b) It's a different user than the one stored.
             // c) No user was stored previously.
             // Essentially, save whenever we *don't* enter the requiresBiometrics state for a non-anonymous user.
             if lastUserID != user.uid || !bioAvailable {
                  try? secureStorage.saveLastUserID(user.uid)
                  print("AuthService Biometrics Check: Saved last user ID (\(user.uid)) as biometrics are not currently required/matched.")
              }
         }
     }

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
        // Optionally clear error when forcing state? Depends on test needs.
        // self.lastError = nil
    }
    #endif

}
