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
            // Use Task.detached if truly necessary, but prefer structured concurrency.
            // For listener callbacks, Task on MainActor is usually sufficient.
            Task { @MainActor [weak self] in
                guard let strongSelf = self else {
                    print("AuthService Listener: Self deallocated before Task execution.")
                    return // Exit if self is nil
                }
                // No need to check isTestMode here if we are inside Task on MainActor bound to self
                guard !strongSelf.isTestMode else {
                    // print("AuthService Listener: Skipping handleAuthStateChange in test mode.") // Keep logs minimal
                    return
                }
                strongSelf.handleAuthStateChange(firebaseUser: user)
            }
        }

        // Initial state check using FirebaseAuth directly
        Task { @MainActor [weak self] in
            guard let strongSelf = self else {
                print("AuthService Initial Check: Self deallocated before Task execution.")
                return
            }
            guard !strongSelf.isTestMode else {
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
        // The responsibility is fully on the consumer to call invalidate().
        // The warning message is removed as we cannot safely check the condition.
        print("AuthService: Deinit finished. Ensure invalidate() was called if a listener was active.")
    }

    // MARK: - Public API (@MainActor)

    // <<< ADDED: invalidate() method >>>
    public func invalidate() {
        print("AuthService: invalidate() called.")
        guard authStateHandle != nil else {
            print("AuthService: invalidate() called, but no listener handle found (already invalidated or never set?).")
            return
        }
        if let handle = authStateHandle {
            print("AuthService: Removing Firebase Auth state listener via invalidate().")
            Auth.auth().removeStateDidChangeListener(handle)
            authStateHandle = nil // Clear the handle
        }
    }

    public func signIn(from viewController: UIViewController) async {
        print("AuthService: signIn requested. Current State: \(state)")
        // <<< ADDED: More explicit guard with logging >>>
        guard state.allowsSignInAttempt else {
            print("AuthService: Sign-in not allowed for current state \(state). Ignoring request.")
            return
        }

        if state == .signedOut {
            resetForNewSignInAttempt()
        } else if state.isPendingResolution || state == .requiresBiometrics {
            print("AuthService: Sign-in attempt from pending/bio state. Clearing previous error only.")
            lastError = nil
        }

        let msg = state.isPendingResolution ? "Linking..." : "Signing in..."
        setState(.authenticating(msg)) // <<< Use setState >>>
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
            await handleSignInAuthError(e) // Sets lastError and state internally
            // Don't dismiss if pending or cancelled (user might want to retry)
            // <<< MODIFIED: Check state *after* error handling >>>
            if state.isPendingResolution || e == .cancelled || state == .requiresBiometrics {
                dismiss = false
            }
        } catch {
            handleSignInGenericError(error) // Sets lastError and state internally
        }

        // Re-evaluate dismissal based on final state AFTER potential error handling
        // Redundant check removed as it's covered above

        if dismiss {
            print("AuthService: Dismissing UI.")
            // Ensure dismissal happens on the main thread, although this method is @MainActor
            viewController.dismiss(animated: true)
        } else {
            print("AuthService: UI remains presented for state: \(state).")
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
                setState(.signedOut) // <<< Use setState >>>
                print("AuthService: (Test Mode) Manually setting state to signedOut.")
            }
            // If not test mode, the listener should handle the state change.
            // However, explicitly setting it ensures immediate UI update if needed.
            // Let's keep the explicit set for now for responsiveness.
                else if state != .signedOut {
                setState(.signedOut) // <<< Use setState >>>
            }
        } catch {
            print("AuthService: Sign out failed: \(error)")
            lastError = AuthError.makeFirebaseAuthError(error)
            clearLocalUserData() // Still clear local data on failure
            setState(.signedOut) // <<< Use setState >>> // Ensure state is signedOut on failure too
        }
    }

    public func authenticateWithBiometrics(reason: String = "Sign in to your account") async {
        print("AuthService: Bio requested. Current State: \(state)")
        // <<< ADDED: Explicit guard for state >>>
        guard state == .requiresBiometrics else {
            print("AuthService WARNING: Biometric authentication requested but state is not .requiresBiometrics (Current: \(state)). Ignoring request.")
            return
        }
        // <<< ADDED: Explicit guard for current user >>>
        guard let currentFirebaseUser = Auth.auth().currentUser else {
            print("AuthService ERROR: Biometric authentication required but no Firebase user is currently signed in. This indicates an inconsistent state. Resetting to signedOut.")
            lastError = .configurationError("Biometrics required but no logged-in user found.")
            clearLocalUserData()
            setState(.signedOut) // <<< Use setState >>>
            return
        }
        let uid = currentFirebaseUser.uid

        setState(.authenticating(biometricAuthenticator.biometryTypeString)) // <<< Use setState >>>
        lastError = nil
        do {
            try await performBiometricAuthentication(reason: reason)
            print("AuthService: Bio successful for user \(uid).")
            // Re-verify user hasn't changed unexpectedly during async bio prompt
            // <<< ADDED: Explicit guard for refreshed user >>>
            guard let refreshedUser = Auth.auth().currentUser, refreshedUser.uid == uid else {
                print("AuthService WARNING: User changed or became nil during biometric authentication. Expected UID \(uid), got \(Auth.auth().currentUser?.uid ?? "nil"). Resetting.")
                lastError = .unknown // Or a more specific error? .configurationError?
                clearLocalUserData()
                setState(.signedOut) // <<< Use setState >>>
                return
            }

            let user = AuthUser(firebaseUser: refreshedUser)
            // Save user ID *after* successful bio auth for non-anonymous user
            // This reinforces the link between the device auth and the user ID.
            // <<< VERIFIED: Saving logic is correctly placed within checkBiometricsRequirement, called implicitly by setting .signedIn below >>>
            // NO! checkBiometricsRequirement IS NOT called here. We transition directly to signedIn.
            // The logic in checkBiometricsRequirement saves ONLY when transitioning TO signedIn *and* conditions are met.
            // Here, we HAVE successfully authenticated. The user IS the same one whose ID is stored.
            // We should directly transition to signedIn. The checkBiometricsRequirement is for INITIAL sign-in or listener updates.

            setState(.signedIn(user)) // <<< Use setState >>> // Directly transition to signedIn
            lastError = nil // Clear error on success
            print("AuthService: State transition to .signedIn after successful biometric auth.")

        } catch let e as AuthError {
            print("AuthService: Bio failed: \(e.localizedDescription)")
            self.lastError = e
            setState(.requiresBiometrics) // <<< Use setState >>> // Stay in requiresBiometrics state
        } catch {
            print("AuthService: Unexpected bio error: \(error)")
            self.lastError = .unknown
            setState(.requiresBiometrics) // <<< Use setState >>> // Stay in requiresBiometrics state
        }
    }

    public func proceedWithMergeConflictResolution() async {
        print("AuthService: proceedWithMerge. Current State: \(state)")
        // <<< ADDED: Explicit guard for state >>>
        guard state == .requiresMergeConflictResolution else {
            print("AuthService WARNING: proceedWithMergeConflictResolution called but state is not .requiresMergeConflictResolution (Current: \(state)). Ignoring request.")
            return
        }
        // <<< ADDED: Explicit guard for credential >>>
        guard let cred = firebaseAuthenticator.existingCredentialForMergeConflict else {
            print("AuthService ERROR: Merge conflict resolution required, but the existing credential is missing. Resetting state.")
            lastError = .missingLinkingInfo
            firebaseAuthenticator.clearTemporaryCredentials() // Ensure cleanup
            emailForLinking = nil // Ensure cleanup
            setState(.signedOut) // <<< Use setState >>>
            return
        }

        setState(.authenticating("Merging accounts...")) // <<< Use setState >>>
        lastError = nil
        do {
            let r = try await Auth.auth().signIn(with: cred)
            let u = AuthUser(firebaseUser: r.user)
            print("AuthService: Merge successful for user \(u.uid). Proceeding to check biometrics.")
            firebaseAuthenticator.clearTemporaryCredentials() // Clear *after* success
            emailForLinking = nil
            lastError = nil // Clear error on success path before async check

            // Check biometrics before setting final state
            checkBiometricsRequirement(for: u) // This will call setState internally

            print("AuthService: Merge conflict resolved. Final state: \(state)")

        } catch {
            print("AuthService ERROR: Merge sign-in failed during conflict resolution: \(error.localizedDescription)")
            lastError = AuthError.makeFirebaseAuthError(error)
            firebaseAuthenticator.clearTemporaryCredentials() // Clear on failure too
            emailForLinking = nil
            setState(.signedOut) // <<< Use setState >>> // Revert to signedOut on merge failure
        }
    }

    public func cancelPendingAction() {
        print("AuthService: cancelPendingAction requested. Current State: \(state)")
        // <<< ADDED: Explicit guard for state >>>
        guard state.isPendingResolution else {
            print("AuthService: Cancel called but state is not pending resolution (\(state)). Ignoring request.")
            return
        }
        print("AuthService: User cancelled pending action from state: \(state)")
        setState(.signedOut) // <<< Use setState >>>
        lastError = nil // Clear error on cancel
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
    }

    // MARK: - Private Helper Methods (@MainActor)

    // <<< ADDED: setState method >>>
    private func setState(_ newState: AuthState) {
        let oldState = self.state
        if oldState == newState {
            // print("AuthService: setState called with the same state (\(newState)). Skipping update.") // Optional: Reduces noise
            return
        }
        // TODO: Replace with structured logging (debug level)
        print("AuthService State Change: \(oldState) -> \(newState)")
        self.state = newState
    }

    private func resetForNewSignInAttempt() {
        print("Resetting internal state for new sign-in attempt.")
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
        // Don't clear lastError here, cleared at start of signIn if needed
        // Don't clear secure storage here
    }

    private func clearLocalUserData() {
        // No async needed here yet as SecureStorageProtocol is sync
        try? secureStorage.clearLastUserID()
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
        // Don't automatically clear lastError here
        print("Cleared local user data (Keychain/SecureStorage, Temp Creds, Email Link).")
    }

    private func performBiometricAuthentication(reason: String) async throws {
        // Wrap the callback-based API in an async function
        try await withCheckedThrowingContinuation { continuation in
            biometricAuthenticator.authenticate(reason: reason) { result in
                switch result {
                case .success:
                    continuation.resume(returning: ())
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // --- COMPLETE SUCCESSFUL SIGN IN ---
    // Handles both standard sign-in and post-link sign-in completion
    private func completeSuccessfulSignIn(user: AuthUser) async {
        print("Completing successful sign-in process for user \(user.uid). Current State before completion: \(state)")

        if let pCred = firebaseAuthenticator.pendingCredentialForLinking {
            // --- Account Linking Path ---
            print("Sign-in successful, now attempting account link...")
            do {
                // Perform link, which internally calls checkBiometricsRequirement on success
                try await performAccountLink(loggedInUser: user, pendingCredential: pCred)
                print("Account linking process completed successfully. Final state: \(state)")
                // lastError and state are set within performAccountLink
            }
            catch { // Catch errors from performAccountLink (already logged inside)
                // State and lastError should already be set by performAccountLink on failure
                print("Account linking process failed. Final state: \(state), Error: \(lastError?.localizedDescription ?? "N/A")")
                // Ensure cleanup just in case performAccountLink didn't fully clean up on error path
                clearLocalUserData()
                // Ensure state is signedOut on any linking failure
                if state != .signedOut {
                    setState(.signedOut)
                }
            }
        } else {
            // --- Standard Sign-in / Post-Merge Path ---
            print("Standard sign-in success or post-merge sign-in completed for user \(user.uid). Checking biometrics...")
            // Clear merge conflict credential if it existed (should have been cleared in proceedWithMergeConflictResolution on success)
            if firebaseAuthenticator.existingCredentialForMergeConflict != nil {
                print("AuthService WARNING: Merge conflict credential was not cleared after successful merge sign-in. Clearing now.")
                firebaseAuthenticator.clearTemporaryCredentials()
                emailForLinking = nil
            }

            lastError = nil // Clear any previous error on this success path before checking biometrics

            // Check biometrics *before* setting final state
            // This function now calls setState internally (.signedIn or .requiresBiometrics)
            // AND handles saving the user ID if appropriate.
            checkBiometricsRequirement(for: user)

            print("Standard sign-in process completed. Final state: \(state)")
            // <<< VERIFIED: Redundant save call was correctly removed previously >>>
        }
    }
    // --- END COMPLETE SUCCESSFUL SIGN IN ---


    private func handleSignInAuthError(_ error: AuthError) async {
        print("AuthService: Handling Sign-In AuthError: \(error.localizedDescription)")
        lastError = error // Set the error state first

        switch error {
        case .accountLinkingRequired(let email):
            // <<< ADDED: Explicit guard for pending credential >>>
            guard firebaseAuthenticator.pendingCredentialForLinking != nil else {
                print("AuthService ERROR: Account linking required error received, but pending credential missing from FirebaseAuthenticator. This indicates an internal inconsistency. Resetting.")
                firebaseAuthenticator.clearTemporaryCredentials() // Ensure cleanup
                emailForLinking = nil // Ensure cleanup
                lastError = .missingLinkingInfo // Overwrite previous error with more specific internal issue
                setState(.signedOut) // <<< Use setState >>>
                return
            }
            self.emailForLinking = email // Store email from the error

            do {
                // Fetch methods requires Firebase interaction, keep await
                let methods = try await Auth.auth().fetchSignInMethods(forEmail: email)
                print("AuthService: Existing sign-in methods for \(email): \(methods.joined(separator: ", "))")
                // Keep lastError as the original .accountLinkingRequired
                setState(.requiresAccountLinking(email: email, existingProviders: methods.sorted())) // <<< Use setState >>>
            } catch let fetchError {
                print("AuthService ERROR: Fetching sign-in methods failed for \(email) during account linking flow: \(fetchError.localizedDescription)")
                lastError = AuthError.makeFirebaseAuthError(fetchError) // Update error to the fetch error
                firebaseAuthenticator.clearTemporaryCredentials() // Clear creds if fetch fails
                emailForLinking = nil
                setState(.signedOut) // <<< Use setState >>> // Fallback if fetch fails
            }

        case .mergeConflictRequired:
            // <<< ADDED: Explicit guard for existing credential >>>
            guard firebaseAuthenticator.existingCredentialForMergeConflict != nil else {
                print("AuthService ERROR: Merge conflict required error received, but existing credential missing from FirebaseAuthenticator. This indicates an internal inconsistency. Resetting.")
                firebaseAuthenticator.clearTemporaryCredentials() // Ensure cleanup
                emailForLinking = nil // Ensure cleanup
                lastError = .missingLinkingInfo // Overwrite previous error
                setState(.signedOut) // <<< Use setState >>>
                return
            }
            // Keep lastError as the original .mergeConflictRequired
            setState(.requiresMergeConflictResolution) // <<< Use setState >>>

        case .cancelled:
            // Don't change state if already in a pending resolution state
            if !state.isPendingResolution {
                print("AuthService: Sign-in cancelled by user. Resetting state.")
                firebaseAuthenticator.clearTemporaryCredentials() // Clear creds on cancel only if not pending
                emailForLinking = nil
                setState(.signedOut) // <<< Use setState >>>
            } else {
                print("AuthService: Sign-in cancelled while in pending state (\(state)). State remains, allowing user to retry or explicitly cancel pending action.")
                // Keep lastError as .cancelled, state remains pending
            }

            // Default case for other errors: revert to signedOut
        default:
            print("AuthService: Unhandled sign-in error (\(error)). Resetting state.")
            firebaseAuthenticator.clearTemporaryCredentials() // Clear creds on general failure
            emailForLinking = nil
            setState(.signedOut) // <<< Use setState >>>
            // Keep the specific lastError that was set at the beginning
        }
    }

    private func handleSignInGenericError(_ error: Error) {
        print("AuthService: Handling Generic Sign-In Error: \(error.localizedDescription)")
        lastError = AuthError.makeFirebaseAuthError(error)
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
        setState(.signedOut) // <<< Use setState >>>
    }

    // --- PERFORM ACCOUNT LINK ---
    private func performAccountLink(loggedInUser: AuthUser, pendingCredential: AuthCredential) async throws {
        print("Attempting to link account for user \(loggedInUser.uid).")
        // <<< ADDED: Explicit guard for Firebase user state >>>
        guard let fbUser = Auth.auth().currentUser, fbUser.uid == loggedInUser.uid else {
            print("AuthService ERROR: User mismatch during account link initiation. Expected \(loggedInUser.uid), but current Firebase user is \(Auth.auth().currentUser?.uid ?? "nil"). Resetting.")
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
            let specificError = AuthError.accountLinkingError("User mismatch during linking initiation.")
            lastError = specificError
            setState(.signedOut) // <<< Use setState >>>
            throw specificError // Throw specific error
        }

        setState(.authenticating("Linking account...")) // <<< Use setState >>>
        lastError = nil

        do {
            let linkResult = try await fbUser.link(with: pendingCredential)
            let updatedUser = AuthUser(firebaseUser: linkResult.user) // Use result user
            print("Link successful! User \(updatedUser.uid) now linked.")

            firebaseAuthenticator.clearTemporaryCredentials() // Clear creds after successful link
            emailForLinking = nil
            lastError = nil

            // Check biometrics AFTER successful linking before setting final state
            // This handles state update (setState) and saving UID if needed.
            checkBiometricsRequirement(for: updatedUser)
            print("Account linking complete. Final state: \(state)")
            // <<< VERIFIED: Redundant save call was correctly removed previously >>>

        } catch {
            print("AuthService ERROR: Account linking failed: \(error.localizedDescription)")
            firebaseAuthenticator.clearTemporaryCredentials() // Clean up on failure
            emailForLinking = nil

            let nsError = error as NSError
            let specificError: AuthError
            if nsError.domain == AuthErrorDomain && nsError.code == AuthErrorCode.credentialAlreadyInUse.rawValue {
                specificError = AuthError.accountLinkingError("This sign-in method is already linked to a different account.")
            } else {
                // Improve detail for other linking errors
                specificError = AuthError.accountLinkingError("Failed to link account. Code: \(nsError.code), Domain: \(nsError.domain)")
            }
            lastError = specificError
            setState(.signedOut) // <<< Use setState >>> // Revert state on linking failure
            throw specificError // Rethrow the specific error
        }
    }
    // --- END PERFORM ACCOUNT LINK ---


    private func handleAuthStateChange(firebaseUser: FirebaseAuth.User?) {
        guard !isTestMode else { return } // Extra safety

        let currentAuthServiceState = self.state // Capture state before potential changes

        if let fbUser = firebaseUser {
            let currentUser = AuthUser(firebaseUser: fbUser)
            print("AuthService Listener: Firebase User PRESENT (UID: \(currentUser.uid)). Current AuthService State: \(currentAuthServiceState)")

            // <<< MODIFIED: More specific logging for ignoring updates >>>
            if currentAuthServiceState.isAuthenticating && currentAuthServiceState != .requiresBiometrics {
                print("AuthService Listener: Ignoring update because AuthService is currently authenticating (but not for biometrics): \(currentAuthServiceState)")
                return
            }
            if currentAuthServiceState.isPendingResolution {
                print("AuthService Listener: Ignoring update because AuthService is pending user resolution: \(currentAuthServiceState)")
                return
            }

            // If already signed in with the *same* user, or requires biometrics for this user, re-check biometrics.
            // This handles cases where biometrics might become available/unavailable, or if the stored ID was somehow cleared.
            if case .signedIn(let existingUser) = currentAuthServiceState, existingUser.uid == currentUser.uid {
                print("AuthService Listener: State already .signedIn with correct user (\(currentUser.uid)). Re-checking biometrics requirement.")
                checkBiometricsRequirement(for: currentUser) // Re-check might change state if needed
                return
            }
            if currentAuthServiceState == .requiresBiometrics {
                // We need to verify if the Firebase user (fbUser) matches the expectation for the .requiresBiometrics state.
                // However, we don't store the expected user in that state. We rely on the keychain.
                // Let's re-run the check; it will confirm if the current fbUser matches the stored ID.
                print("AuthService Listener: State is .requiresBiometrics. Re-checking biometrics requirement against current Firebase user \(currentUser.uid).")
                checkBiometricsRequirement(for: currentUser) // Re-check might transition to signedIn or stay requiresBiometrics
                return
            }

            // If the state wasn't signedIn(correctUser) or requiresBiometrics,
            // but we *do* have a Firebase user, it means our state was out of sync or
            // this is the initial notification after a successful sign-in flow completed.
            // Update our state based on the listener's user.
            print("AuthService Listener: Firebase user present, but AuthService state was \(currentAuthServiceState). Updating state based on listener.")
            checkBiometricsRequirement(for: currentUser) // This will set state to signedIn or requiresBiometrics

        } else {
            // Firebase User is ABSENT (nil)
            print("AuthService Listener: Firebase User ABSENT. Current AuthService State: \(currentAuthServiceState)")

            // Only change state to signedOut if we weren't already signedOut
            // and are not currently in the middle of an authentication attempt.
            if currentAuthServiceState != .signedOut && !currentAuthServiceState.isAuthenticating {
                print("AuthService Listener: Firebase user became nil. Clearing local data and setting state to signedOut.")
                clearLocalUserData()
                lastError = nil // Clear error on listener-driven sign-out
                setState(.signedOut) // <<< Use setState >>>
            } else {
                print("AuthService Listener: Firebase user is nil, but AuthService state is already \(currentAuthServiceState). No state change needed based on this event.")
            }
        }
    }

    // --- Biometrics Check (Handles state setting and saving) ---
    // <<< VERIFIED: User ID saving is correctly centralized here >>>
    // This function now calls setState internally.
    private func checkBiometricsRequirement(for user: AuthUser) {
        guard !user.isAnonymous else {
            print("AuthService Biometrics Check: Skipping for anonymous user \(user.uid). Setting state to signedIn.")
            // Use setState to ensure logging and prevent direct assignment
            setState(.signedIn(user))
            return
        }

        // Retrieve last user ID (still sync for now)
        let lastUserID = secureStorage.getLastUserID()
        let bioAvailable = biometricAuthenticator.isBiometricsAvailable
        print("AuthService Biometrics Check: User: \(user.uid), Stored UID: \(lastUserID ?? "nil"), Biometrics Available: \(bioAvailable)")

        // Determine target state based on biometrics
        let targetState: AuthState
        if bioAvailable && lastUserID == user.uid {
            targetState = .requiresBiometrics
            print("AuthService Biometrics Check: Conditions met for .requiresBiometrics.")
        } else {
            targetState = .signedIn(user)
            print("AuthService Biometrics Check: Conditions met for .signedIn (User: \(user.uid), Stored: \(lastUserID ?? "nil"), Bio Available: \(bioAvailable)).")

            // Save User ID ONLY if we are transitioning to or confirming the simple .signedIn state
            // AND the ID needs updating (different user or first time saving) OR bio just became unavailable.
            // This prevents saving again after successful biometric auth (where targetState would be .signedIn but lastUserID *would* match).
            if lastUserID != user.uid || !bioAvailable {
                print("AuthService Biometrics Check: Saving User ID \(user.uid) because stored ID is different (\(lastUserID ?? "nil")) or biometrics not available (\(bioAvailable)).")
                // Error handling for save can be added if protocol becomes async throws
                try? secureStorage.saveLastUserID(user.uid)
            }
        }

        // Update the state using the central method
        setState(targetState)
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
            // Use the central setter for consistency, though less critical in tests
            self.setState(state)
        }
    #endif
}
