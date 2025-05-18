import Foundation
import Combine
import FirebaseAuth // For AuthCredential, User, etc.
import UIKit // For UIViewController

@MainActor
public class AuthService: ObservableObject, AuthServiceProtocol {

    @Published public private(set) var state: AuthState = .signedOut
    @Published public private(set) var lastError: AuthError? = nil

    public var statePublisher: Published<AuthState>.Publisher { $state }
    public var lastErrorPublisher: Published<AuthError?>.Publisher { $lastError }

    public var biometryTypeString: String {
        return biometricAuthenticator.biometryTypeString
    }

    // Dependencies
    private let config: AuthConfig
    private let firebaseAuthenticator: FirebaseAuthenticatorProtocol
    private let biometricAuthenticator: BiometricAuthenticatorProtocol
    private let secureStorage: SecureStorageProtocol

    // Internal State
    private var authStateHandle: AuthStateDidChangeListenerHandle?
    private var cancellables = Set<AnyCancellable>()
    internal let isTestMode: Bool

    // Stores the credential from an initial failed sign-in (e.g. tried Apple, but account exists with Google)
    // This is the credential we want to *link* after the user re-authenticates with their existing method.
    internal var pendingCredentialToLinkAfterReauth: AuthCredential?
    private var emailForLinking: String?

    // Designated Initializer (Internal - for DI and testing)
    internal init(
        config: AuthConfig,
        secureStorage: SecureStorageProtocol,
        firebaseAuthenticator: FirebaseAuthenticatorProtocol,
        biometricAuthenticator: BiometricAuthenticatorProtocol,
        isTestMode: Bool = false
    ) {
        self.config = config
        self.secureStorage = secureStorage
        self.firebaseAuthenticator = firebaseAuthenticator
        self.biometricAuthenticator = biometricAuthenticator
        self.isTestMode = isTestMode
        print("AuthService (Direct): Initializing. Test Mode: \(isTestMode)")

        self.authStateHandle = Auth.auth().addStateDidChangeListener { [weak self] (_, user) in
            Task { @MainActor [weak self] in // Ensure MainActor context
                guard let strongSelf = self else { return }
                guard !strongSelf.isTestMode else { return } // Don't run listener logic in pure test mode where state is forced
                await strongSelf.handleAuthStateChange(firebaseUser: user)
            }
        }
        // Also check initial state, especially if app launches quickly or listener setup is delayed
        Task { @MainActor [weak self] in // Ensure MainActor context
            guard let strongSelf = self else { return }
            guard !strongSelf.isTestMode else { return }
            await strongSelf.handleAuthStateChange(firebaseUser: Auth.auth().currentUser)
        }
        print("AuthService (Direct): Init complete, listener added.")
    }

    // Convenience Initializer (Public - for production use)
    public convenience init(config: AuthConfig) {
        let storage = KeychainStorage(accessGroup: config.keychainAccessGroup)
        let bioAuth = BiometricAuthenticator()
        // Pass the config to FirebaseAuthenticator (though it might not use all parts if FUI is gone)
        let fireAuth = FirebaseAuthenticator(config: config, secureStorage: storage)
        self.init(
            config: config,
            secureStorage: storage,
            firebaseAuthenticator: fireAuth,
            biometricAuthenticator: bioAuth
        )
        print("AuthService (Direct): Convenience Init completed.")
    }

    deinit {
        // The authStateHandle is automatically removed by Firebase when the listener object (AuthService) is deallocated,
        // if it wasn't removed by an explicit invalidate() call earlier.
        // However, explicit invalidate() by the owner is still best practice for Combine cancellables.
        print("AuthService (Direct): Deinit.")
    }

    // MARK: - Public API - Lifecycle
    public func invalidate() {
        if let handle = authStateHandle {
            Auth.auth().removeStateDidChangeListener(handle)
            authStateHandle = nil
            print("AuthService (Direct): Firebase Auth state listener removed via invalidate().")
        }
        cancellables.forEach { $0.cancel() } // Cancel any Combine subscriptions
    }

    // MARK: - Public API - Core Authentication Methods

    public func signInWithEmail(email: String, password: String) async {
        await performAuthOperation(
            authAction: { try await self.firebaseAuthenticator.signInWithEmail(email: email, password: password) },
            authActionType: .signIn
        )
    }

    public func createAccountWithEmail(email: String, password: String, displayName: String? = nil) async {
        await performAuthOperation(
            authAction: { try await self.firebaseAuthenticator.createAccountWithEmail(email: email, password: password, displayName: displayName) },
            authActionType: .signUp
        )
    }

    public func signInWithGoogle(presentingViewController: UIViewController) async {
        await performAuthOperation(
            authAction: { try await self.firebaseAuthenticator.signInWithGoogle(presentingViewController: presentingViewController) },
            authActionType: .signIn
        )
    }

    public func signInWithApple(presentingViewController: UIViewController) async {
        let rawNonce = AuthUtilities.randomNonceString()
        // The hashed nonce is created and used within FirebaseAuthenticator now
        await performAuthOperation(
            authAction: { try await self.firebaseAuthenticator.signInWithApple(presentingViewController: presentingViewController, rawNonce: rawNonce) },
            authActionType: .signIn
        )
    }

    public func sendPasswordResetEmail(to email: String) async {
        guard !email.isEmpty else {
            lastError = .configurationError("Email address cannot be empty for password reset.")
            return
        }
        
        // Store if we were already in an auth flow initiated by another operation.
        // This helps decide if this method should be responsible for reverting the .authenticating state.
        let wasAlreadyAuthenticating = state.isAuthenticating
        setState(.authenticating("Sending Reset Email..."))
        lastError = nil
        
        do {
            try await firebaseAuthenticator.sendPasswordResetEmail(to: email)
            // What state to go to here? Usually, stay on the current screen and show a success message.
            // For simplicity, AuthService doesn't manage a dedicated "passwordResetEmailSent" state.
            // The UI should handle displaying a confirmation.
            print("AuthService: Password reset email initiated for \(email).")
            // UI should show a message like "If an account exists for this email, a reset link has been sent."
            
            // --- START CHANGE 1: sendPasswordResetEmail state handling ---
            // If this method set the state to .authenticating("Sending Reset Email..."),
            // then it's responsible for reverting it.
            // We revert to a state consistent with the current Firebase user.
            if !wasAlreadyAuthenticating {
                if let firebaseUser = Auth.auth().currentUser {
                    // User is still signed in (or was signed in), re-check biometrics or set to signedIn
                    await checkBiometricsRequirement(for: AuthUser(firebaseUser: firebaseUser))
                } else {
                    // No current Firebase user, so go to signedOut
                    setState(.signedOut)
                }
            }
            // If wasAlreadyAuthenticating was true, another operation is in progress,
            // and this password reset was a side-task. Let the main auth flow resolve the state.
            // --- END CHANGE 1 ---
        } catch let e as AuthError {
            lastError = e
            // --- START CHANGE 1 (Error Path): sendPasswordResetEmail state handling ---
            if !wasAlreadyAuthenticating {
                if let firebaseUser = Auth.auth().currentUser {
                     await checkBiometricsRequirement(for: AuthUser(firebaseUser: firebaseUser))
                } else {
                    setState(.signedOut)
                }
            }
            // --- END CHANGE 1 (Error Path) ---
        } catch {
            lastError = .unknown
            // --- START CHANGE 1 (Generic Error Path): sendPasswordResetEmail state handling ---
            if !wasAlreadyAuthenticating {
                if let firebaseUser = Auth.auth().currentUser {
                     await checkBiometricsRequirement(for: AuthUser(firebaseUser: firebaseUser))
                } else {
                    setState(.signedOut)
                }
            }
            // --- END CHANGE 1 (Generic Error Path) ---
        }
    }

    public func signOut() {
        print("AuthService: signOut requested.")
        self.pendingCredentialToLinkAfterReauth = nil
        self.firebaseAuthenticator.clearTemporaryCredentials()

        do {
            try Auth.auth().signOut() // This part is synchronous
            print("AuthService: Firebase sign-out call successful.")
            // Explicitly clear local data and set state immediately
            // The listener will still fire but should find the state already correct.
            clearLocalUserDataAndSetSignedOutState() // <<<< CALL IT HERE
            lastError = nil // Ensure error is cleared on successful sign-out
            print("AuthService: State set to signedOut and local data cleared synchronously after sign out call.")
        } catch {
            print("AuthService: Sign out failed: \(error.localizedDescription)")
            lastError = AuthError.makeFirebaseAuthError(error)
            clearLocalUserDataAndSetSignedOutState() // Also ensure cleanup on error
        }
    }

    // MARK: - Public API - State Resolution Methods

    public func authenticateWithBiometrics(reason: String = "Sign in to your account") async {
        // Implementation similar to before, but ensures no FirebaseUI interaction
        guard state == .requiresBiometrics else {
            print("AuthService: Biometric auth requested but not in .requiresBiometrics state.")
            return
        }
        guard let currentFirebaseUser = Auth.auth().currentUser else {
            lastError = .configurationError("Biometrics required but no Firebase user found.")
            clearLocalUserDataAndSetSignedOutState()
            return
        }
        let uid = currentFirebaseUser.uid

        setState(.authenticating(biometricAuthenticator.biometryTypeString))
        lastError = nil
        do {
            try await performBiometricAuthenticationInternal(reason: reason) // Renamed internal helper

            guard let refreshedUser = Auth.auth().currentUser, refreshedUser.uid == uid else {
                lastError = .unknown // User changed during bio auth
                clearLocalUserDataAndSetSignedOutState()
                return
            }
            setState(.signedIn(AuthUser(firebaseUser: refreshedUser))) // Successfully signed in via biometrics
        } catch let e as AuthError {
            lastError = e
            setState(.requiresBiometrics) // Stay in requiresBiometrics on failure
        } catch {
            lastError = .unknown
            setState(.requiresBiometrics) // Stay in requiresBiometrics on failure
        }
    }

    // This method is called when the user cancels a linking/merge flow from the UI
    public func cancelPendingAction() {
        print("AuthService: cancelPendingAction requested. Current State: \(state)")
        guard state.isPendingResolution else {
            print("AuthService: Cancel called but state is not pending resolution (\(state)). Ignoring.")
            return
        }
        self.pendingCredentialToLinkAfterReauth = nil
        firebaseAuthenticator.clearTemporaryCredentials()
        lastError = nil // Clear any linking-related error
        setState(.signedOut)
    }

    // MARK: - Auth Operation Orchestration

    internal enum AuthActionType { case signIn, signUp, link }

    // AuthService.swift
    private func performAuthOperation(
        authAction: @escaping () async throws -> AuthUser,
        authActionType: AuthActionType // signIn, signUp, link (link might not be used as an explicit type here)
    ) async {
        // Determine if this is a re-authentication step in a linking flow
        let isReAuthForLinking = (self.pendingCredentialToLinkAfterReauth != nil && authActionType == .signIn)

        if !isReAuthForLinking {
            // This is a fresh sign-in or sign-up attempt
            guard state.allowsSignInAttempt(for: authActionType) else {
                print("AuthService: Auth operation not allowed for current state \(state) and action type \(authActionType).")
                // Potentially set an error here if this is a programmatic mistake
                // self.lastError = .configurationError("Auth operation not allowed in current state.")
                return
            }
            resetForNewAuthAttempt() // Clears lastError, previous pendingCredential, etc.
            setState(.authenticating(authActionType == .signUp ? "Creating Account..." : "Signing In..."))
        } else {
            // This is a re-authentication step during linking
            // Keep existing lastError (which should be .accountLinkingRequired)
            // Keep existing pendingCredentialToLinkAfterReauth
            // Keep existing emailForLinking
            setState(.authenticating("Verifying existing account..."))
        }

        do {
            let user = try await authAction() // Perform the actual email sign-in, Google sign-in, etc.

            if let credentialToLink = self.pendingCredentialToLinkAfterReauth, isReAuthForLinking {
                // Condition 'isReAuthForLinking' ensures authActionType was .signIn and pendingCred was present
                print("AuthService: Re-authentication successful for linking. User: \(user.uid). Attempting to link stored credential.")
                await completeAccountLinking(loggedInUser: user, credentialToLink: credentialToLink)
            } else if self.pendingCredentialToLinkAfterReauth != nil && authActionType == .signUp {
                // This case should ideally not happen if sign-up during linking isn't allowed.
                // If a sign-up happens while a link is pending, what's the desired behavior?
                // For now, treat as a new user, link is abandoned.
                print("AuthService WARNING: Sign-up occurred while a link was pending. Abandoning link. New user: \(user.uid)")
                self.pendingCredentialToLinkAfterReauth = nil
                self.firebaseAuthenticator.clearTemporaryCredentials()
                await checkBiometricsRequirement(for: user) // Process this new user
            }
            else {
                // Standard sign-in or sign-up success (not part of a linking re-auth flow)
                print("AuthService: Auth operation successful. User: \(user.uid).")
                // Ensure pendingCredentialToLinkAfterReauth is nil if we reach here without linking
                if self.pendingCredentialToLinkAfterReauth != nil {
                    print("AuthService WARNING: Auth succeeded but an unhandled pending credential existed. Clearing it now.")
                    self.pendingCredentialToLinkAfterReauth = nil
                    self.firebaseAuthenticator.clearTemporaryCredentials() // Clear associated authenticator state too
                }
                await checkBiometricsRequirement(for: user)
            }
        } catch let e as AuthError {
            // If the re-auth attempt itself fails (e.g. wrong password for email re-auth)
            // handleAuthOperationError will be called. It needs to preserve the linking context.
            await handleAuthOperationError(e, authActionType: authActionType, wasReAuthForLinking: isReAuthForLinking)
        } catch {
            // ... (generic error handling as before)
            print("AuthService: Unknown error during auth operation: \(error.localizedDescription)")
            lastError = .unknown
            if !isReAuthForLinking { // Only fully reset if not a failed re-auth for linking
                clearLocalUserDataAndSetSignedOutState()
            } else {
                // If it was a re-auth for linking that failed with an unknown error,
                // revert to .requiresAccountLinking state.
                // Ensure providers list is handled consistently (currently empty).
                setState(.requiresAccountLinking(email: self.emailForLinking ?? "linking email", existingProviders: []))
            }
        }
    }

    private func handleAuthOperationError(_ error: AuthError, authActionType: AuthActionType, wasReAuthForLinking: Bool = false) async {
        print("AuthService: Handling AuthError: \(error.localizedDescription) for action: \(authActionType)")
        self.lastError = error // Always set the most recent error

        switch error {
        case .accountLinkingRequired(let email, let credentialToLink):
            // This error comes from FirebaseAuthenticator.processFirebaseError
            // It means an account exists for 'email', and 'credentialToLink' is what the user just tried.
            self.pendingCredentialToLinkAfterReauth = credentialToLink // Store this for after re-auth
            self.emailForLinking = email // Store email for UI and potential re-fetch

            // --- START CHANGE 3: existingProviders comment update ---
            let methods: [String] = [] // TODO: Ideally, fetch actual providers using Auth.auth().fetchSignInMethods(forEmail: email).
                                       // For now, UI must handle fetching these if needed to guide the user more specifically.
                                       // See README for example UI logic.
            // --- END CHANGE 3 ---
            print("AuthService: Existing sign-in methods for \(email): \(methods.joined(separator: ", ")) (Note: list is currently hardcoded empty)")
            // Pass the *original* pending credential (if any) to the state for context,
            // though UI might not directly use it for display.
            setState(.requiresAccountLinking(email: email, existingProviders: methods.sorted()))

        case .mergeConflictError(_):
            // This error would also come from FirebaseAuthenticator if it detects a situation
            // that requires a merge. The credentials would be part of the error.
            // For now, we'll just set the state. Actual merge logic needs Firebase User input.
            setState(.requiresMergeConflictResolution) // Need to adapt AuthState for this if we keep it

        case .cancelled:
            if wasReAuthForLinking { // If user cancelled the Google/Apple UI during re-auth
                print("AuthService: Re-authentication for linking cancelled. Staying in .requiresAccountLinking.")
                // Ensure state reverts to .requiresAccountLinking with the original email and pending cred
                // (providers list remains empty based on current logic)
                setState(.requiresAccountLinking(email: self.emailForLinking ?? "linking email", existingProviders: []))
            } else {
                // Standard cancellation of initial sign-in/sign-up
                clearLocalUserDataAndSetSignedOutState()
            }

        case .reauthenticationRequired:
            // This is a specific error that needs UI to prompt for re-auth.
            // For now, just log and revert. A more complete flow would handle this.
            print("AuthService: Reauthentication required. App UI needs to handle this flow.")
            clearLocalUserDataAndSetSignedOutState() // Simplistic handling for now

        default:
            // For other errors:
            if wasReAuthForLinking {
                // The re-auth attempt itself failed (e.g., wrong password).
                // lastError is already set.
                // Stay in .requiresAccountLinking to allow another attempt or cancellation by user.
                print("AuthService: Re-authentication for linking failed with error. Staying in .requiresAccountLinking.")
                // (providers list remains empty based on current logic)
                setState(.requiresAccountLinking(email: self.emailForLinking ?? "linking email", existingProviders: []))
            } else if !state.isPendingResolution {
                // If not a re-auth for linking AND not already in a pending resolution state,
                // then clear user data and go to signedOut.
                clearLocalUserDataAndSetSignedOutState()
            }
            // If we ARE in a pending state (e.g. .requiresAccountLinking) and the re-auth attempt
            // itself fails with an error other than .cancelled (e.g. wrong password),
            // lastError is set, and the state remains .requiresAccountLinking, allowing another try.
        }
    }


    // MARK: - Account Linking Specific Logic

    private func completeAccountLinking(loggedInUser: AuthUser, credentialToLink: AuthCredential) async {
        guard let firebaseUser = Auth.auth().currentUser, firebaseUser.uid == loggedInUser.uid else {
            print("AuthService ERROR: User mismatch during account link finalization.")
            self.lastError = .accountLinkingError("User mismatch during link finalization.")
            clearLocalUserDataAndSetSignedOutState() // Clears pending creds
            return
        }

        setState(.authenticating("Linking Account..."))
        // Don't clear lastError yet, it might be the .accountLinkingRequired error that led here.

        do {
            let updatedUser = try await firebaseAuthenticator.linkCredential(credentialToLink, to: firebaseUser)
            print("AuthService: Account linking successful! Final user UID: \(updatedUser.uid)")
            self.lastError = nil // Clear error on successful link
            self.pendingCredentialToLinkAfterReauth = nil
            firebaseAuthenticator.clearTemporaryCredentials()
            await checkBiometricsRequirement(for: updatedUser) // Final state update
        } catch let e as AuthError {
            print("AuthService: Account linking failed: \(e.localizedDescription)")
            // If linking failed (e.g. credentialAlreadyInUse by a *third* account),
            // lastError is updated. What state to go to?
            // Reverting to signedOut is safest unless we have a specific merge flow for this.
            self.lastError = e // Update with the new linking error
            clearLocalUserDataAndSetSignedOutState() // This will clear pendingCredentialToLinkAfterReauth
        } catch {
            print("AuthService: Unknown error during account linking finalization: \(error.localizedDescription)")
            self.lastError = .unknown
            clearLocalUserDataAndSetSignedOutState() // This will clear pendingCredentialToLinkAfterReauth
        }
    }

    // --- START CHANGE 2: API Cleanup ---
    // `proceedWithAccountLink` method and its comments REMOVED.
    // `proceedWithMergeConflictResolution` method and its comments REMOVED.
    // --- END CHANGE 2 ---


    // MARK: - Private Helper Methods
    private func setState(_ newState: AuthState) {
        let oldState = self.state
        if oldState == newState {
            // If the state is the same but it's an error state, ensure lastError is also considered.
            // This check is mostly to avoid redundant print statements if nothing truly changed.
            if case .requiresAccountLinking(let lEmail, let lProviders) = newState,
               case .requiresAccountLinking(let rEmail, let rProviders) = oldState {
                // Allow if email or providers changed, or if lastError changed
                // For now, providers don't change in this state from AuthService, so email and lastError are key.
                if lEmail == rEmail && lProviders == rProviders { // Basic check, lastError is observed separately
                    // return // Could return if we are sure no other context change (like lastError) needs processing
                }
            } else {
                 return
            }
        }
        print("AuthService State Change: \(oldState) -> \(newState)")
        self.state = newState
    }

    private func resetForNewAuthAttempt() {
        print("AuthService: Resetting for new auth attempt.")
        lastError = nil
        pendingCredentialToLinkAfterReauth = nil
        firebaseAuthenticator.clearTemporaryCredentials() // Important!
        emailForLinking = nil
    }

    private func clearLocalUserDataAndSetSignedOutState() {
        Task { // Fire and forget for keychain
            try? await secureStorage.clearLastUserID()
            print("AuthService: Cleared last user ID from secure storage.")
        }
        // pendingCredentialToLinkAfterReauth and authenticator creds should be cleared by calling context or signOut
        if pendingCredentialToLinkAfterReauth != nil {
            pendingCredentialToLinkAfterReauth = nil
            print("AuthService: Cleared pendingCredentialToLinkAfterReauth in clearLocalUserDataAndSetSignedOutState.")
        }
        firebaseAuthenticator.clearTemporaryCredentials() // Ensure authenticator's temp creds are also cleared
        emailForLinking = nil
        setState(.signedOut)
    }

    private func performBiometricAuthenticationInternal(reason: String) async throws {
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

    // MARK: - Firebase Auth State Listener & Biometrics Logic (Largely Unchanged)

    private func handleAuthStateChange(firebaseUser: FirebaseAuth.User?) async {
        // This guard should already be in the init call to addStateDidChangeListener, but double-check
        guard !isTestMode else {
            print("AuthService Listener: In test mode, listener ignored.")
            return
        }
        let currentAuthServiceState = self.state // Capture state at the beginning of this async task

        if let fbUser = firebaseUser {
            let currentUser = AuthUser(firebaseUser: fbUser)
            print("AuthService Listener: Firebase User PRESENT (UID: \(currentUser.uid)). Current AuthService State: \(currentAuthServiceState)")

            // Avoid interrupting an ongoing, user-initiated auth flow or resolution flow
            // Check currentAuthServiceState, not self.state which might have changed if other async tasks run
            if currentAuthServiceState.isAuthenticating && currentAuthServiceState != .requiresBiometrics {
                print("AuthService Listener: Ignoring update (AuthService currently busy: \(currentAuthServiceState))")
                return
            }
            if currentAuthServiceState.isPendingResolution { // e.g., .requiresAccountLinking
                print("AuthService Listener: Ignoring update (AuthService currently pending resolution: \(currentAuthServiceState))")
                return
            }

            // If already signedIn with the same user, or requiresBiometrics for this user, re-check biometrics.
            // This handles cases like app coming to foreground or biometrics settings changing.
            // Compare with self.state here, as it's the most up-to-date at this point of execution.
            if (self.state == .signedIn(currentUser) && !currentUser.isAnonymous) || self.state == .requiresBiometrics {
                print("AuthService Listener: User \(currentUser.uid) already matches current state or requires biometrics. Re-evaluating biometrics.")
                await checkBiometricsRequirement(for: currentUser) // This will call setState if needed
                return
            }

            // If user is present, but state is not signedIn or requiresBio for this user, transition.
            print("AuthService Listener: Firebase user \(currentUser.uid) present. Current AuthService state \(self.state) is different. Updating state based on new Firebase user.")
            await checkBiometricsRequirement(for: currentUser) // This will call setState

        } else { // Firebase User is ABSENT (nil)
            print("AuthService Listener: Firebase User ABSENT. Current AuthService State: \(currentAuthServiceState)")

            // Only transition to signedOut if we are not already signedOut AND not in the middle of an auth attempt
            // (e.g., user just tried to sign in, it failed, and then listener fires with nil).
            // The auth operation itself should handle setting to signedOut on failure.
            // This listener mainly handles external changes (e.g., token revoked, user deleted from console).
            if currentAuthServiceState != .signedOut && !currentAuthServiceState.isAuthenticating {
                print("AuthService Listener: Firebase user became nil. Clearing local data and setting state to signedOut.")
                clearLocalUserDataAndSetSignedOutState() // This also sets state to signedOut
                lastError = nil // Clear any lingering error from previous session
            } else if currentAuthServiceState == .signedOut {
                print("AuthService Listener: Firebase user is nil, state is already .signedOut. No state change needed from listener.")
            } else { // currentAuthServiceState.isAuthenticating
                print("AuthService Listener: Firebase user is nil, but an auth operation is in progress (\(currentAuthServiceState)). Letting operation complete or fail.")
                // The auth operation itself should handle its outcome (e.g., setting .signedOut on failure).
            }
        }
    }

    private func checkBiometricsRequirement(for user: AuthUser) async {
        guard !user.isAnonymous else {
            print("AuthService Biometrics Check: Skipping for anonymous user \(user.uid). Setting state to signedIn.")
            setState(.signedIn(user))
            return
        }
        // This internal helper determines the state and then setState is called with its result.
        let determinedState = await determineBiometricStateInternal(for: user)
        setState(determinedState)
    }

    private func determineBiometricStateInternal(for user: AuthUser) async -> AuthState {
        // This guard should ideally be caught by the caller (checkBiometricsRequirement),
        // but as a safeguard within this internal logic.
        guard !user.isAnonymous else { return .signedIn(user) }

        let lastUserID = await secureStorage.getLastUserID()
        let bioAvailable = biometricAuthenticator.isBiometricsAvailable
        print("AuthService Biometrics Logic: User \(user.uid). Stored UID: \(lastUserID ?? "nil"). Bio Available: \(bioAvailable).")

        if bioAvailable && lastUserID == user.uid {
            // User is known, biometrics are available and were likely used/set up before.
            return .requiresBiometrics
        } else {
            // Conditions to save/update User ID in secure storage:
            // 1. It's a new user signing in (lastUserID != user.uid).
            // 2. It's the same user, but biometrics just became unavailable (so we shouldn't prompt next time, just sign in).
            // 3. Biometrics is available, but lastUserID was nil (first non-anonymous sign-in on this device).
            // Essentially, save if it's a non-anonymous user and they are not going into .requiresBiometrics state.
            if lastUserID != user.uid || (lastUserID == user.uid && !bioAvailable) || (bioAvailable && lastUserID == nil) {
                print("AuthService Biometrics Logic: Saving User ID \(user.uid) to secure storage. Reason: lastUID='\(lastUserID ?? "nil")', bioAvailable=\(bioAvailable).")
                do {
                    try await secureStorage.saveLastUserID(user.uid)
                } catch {
                    // Log the error. Depending on app requirements, this could be more critical.
                    print("AuthService Biometrics WARNING: Failed to save User ID \(user.uid) to secure storage: \(error.localizedDescription)")
                    // Potentially set lastError here if this is critical, e.g., self.lastError = .keychainError(...)
                    // However, failing to save UID for biometrics shouldn't block sign-in.
                }
            }
            return .signedIn(user)
        }
    }

    // MARK: - Test Helpers
    #if DEBUG
        @MainActor
        internal func forceStateForTesting(_ state: AuthState) {
            guard isTestMode else { return }
            print("AuthService (Test Mode): Forcing state to \(state)")
            self.setState(state) // Use the internal setState to ensure printout
        }
    #endif
}

// Extension to AuthState for allowsSignInAttempt refinement
fileprivate extension AuthState {
    func allowsSignInAttempt(for actionType: AuthService.AuthActionType) -> Bool {
        switch self {
        case .signedOut:
            return true // Always allow from signedOut
        case .requiresBiometrics:
            // Allow if user is trying to sign in with a different method (e.g. password) instead of biometrics
            return actionType == .signIn
        case .requiresAccountLinking, .requiresMergeConflictResolution:
            // Allow if it's a signIn action (which is the re-authentication step for linking/merging)
            return actionType == .signIn
        case .authenticating, .signedIn:
            return false // Not allowed if already signed in or in the middle of another auth process
        }
    }
}
