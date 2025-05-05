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

    // Dependencies
    private let config: AuthConfig
    private let firebaseAuthenticator: FirebaseAuthenticatorProtocol
    private let biometricAuthenticator: BiometricAuthenticatorProtocol
    private let secureStorage: SecureStorageProtocol

    // Internal State
    private var authStateHandle: AuthStateDidChangeListenerHandle?
    private var cancellables = Set<AnyCancellable>()
    private var emailForLinking: String? // Stores email during linking flow
    private let isTestMode: Bool

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
        print("AuthService (Designated Init): Initializing with injected dependencies. Test Mode: \(isTestMode)")

        // Setup listener using FirebaseAuth directly
        self.authStateHandle = Auth.auth().addStateDidChangeListener { [weak self] (_, user) in
            Task { @MainActor [weak self] in
                guard let strongSelf = self else {
                    print("AuthService Listener: Self deallocated before Task execution.")
                    return
                }
                guard !strongSelf.isTestMode else {
                    return
                }
                await strongSelf.handleAuthStateChange(firebaseUser: user)
            }
        }

        // Initial state check using FirebaseAuth directly
        Task { @MainActor [weak self] in
            guard let strongSelf = self else {
                print("AuthService Initial Check: Self deallocated before Task execution.")
                return
            }
            guard !strongSelf.isTestMode else {
                return
            }
            await strongSelf.handleAuthStateChange(firebaseUser: Auth.auth().currentUser)
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
        print("AuthService: Deinit finished. Ensure invalidate() was called if a listener was active.")
    }

    // MARK: - Public API (@MainActor)

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
        setState(.authenticating(msg))
        if !state.isPendingResolution {
            lastError = nil
        }

        var dismiss = true

        do {
            let user = try await firebaseAuthenticator.presentSignInUI(from: viewController)
            await handleSuccessfulSignIn(user: user)
            
        } catch let e as AuthError {
            await handleSignInAuthError(e)
            if state.isPendingResolution || e == .cancelled || state == .requiresBiometrics {
                dismiss = false
            }
            
        } catch {
            handleSignInGenericError(error)
        }

        if dismiss {
            print("AuthService: Dismissing UI.")
            viewController.dismiss(animated: true)
        } else {
            print("AuthService: UI remains presented for state: \(state).")
        }
    }

    public func signOut() {
        print("AuthService: signOut requested.")
        do {
            try Auth.auth().signOut()
            clearLocalUserData() // Clears keychain/storage async internally
            lastError = nil
            print("AuthService: Sign out OK.")
            // Always explicitly set state, listener might lag or not fire in all edge cases.
            setState(.signedOut)
             if isTestMode {
                 print("AuthService: (Test Mode) State set to signedOut.")
             }
        } catch {
            print("AuthService: Sign out failed: \(error)")
            lastError = AuthError.makeFirebaseAuthError(error)
            clearLocalUserData()
            setState(.signedOut)
        }
    }

    public func authenticateWithBiometrics(reason: String = "Sign in to your account") async {
        print("AuthService: Bio requested. Current State: \(state)")
        guard state == .requiresBiometrics else {
            print("AuthService WARNING: Biometric authentication requested but state is not .requiresBiometrics (Current: \(state)). Ignoring request.")
            return
        }
        guard let currentFirebaseUser = Auth.auth().currentUser else {
            print("AuthService ERROR: Biometric authentication required but no Firebase user is currently signed in. Resetting to signedOut.")
            lastError = .configurationError("Biometrics required but no logged-in user found.")
            clearLocalUserData()
            setState(.signedOut)
            return
        }
        let uid = currentFirebaseUser.uid

        setState(.authenticating(biometricAuthenticator.biometryTypeString))
        lastError = nil
        do {
            try await performBiometricAuthentication(reason: reason)
            print("AuthService: Bio successful for user \(uid).")

            guard let refreshedUser = Auth.auth().currentUser, refreshedUser.uid == uid else {
                print("AuthService WARNING: User changed or became nil during biometric authentication. Resetting.")
                lastError = .unknown
                clearLocalUserData()
                setState(.signedOut)
                return
            }

            let user = AuthUser(firebaseUser: refreshedUser)
            // Directly transition to signedIn after successful bio auth.
            // Saving ID isn't needed here as it was the condition for requiresBiometrics.
            setState(.signedIn(user))
            lastError = nil
            print("AuthService: State transition to .signedIn after successful biometric auth.")

        } catch let e as AuthError {
            print("AuthService: Bio failed: \(e.localizedDescription)")
            self.lastError = e
            setState(.requiresBiometrics) // Stay in requiresBiometrics state
        } catch {
            print("AuthService: Unexpected bio error: \(error)")
            self.lastError = .unknown
            setState(.requiresBiometrics) // Stay in requiresBiometrics state
        }
    }

    public func proceedWithMergeConflictResolution() async {
        print("AuthService: proceedWithMerge. Current State: \(state)")
        guard state == .requiresMergeConflictResolution else {
            print("AuthService WARNING: proceedWithMergeConflictResolution called but state is not .requiresMergeConflictResolution (Current: \(state)). Ignoring request.")
            return
        }
        guard let cred = firebaseAuthenticator.existingCredentialForMergeConflict else {
            print("AuthService ERROR: Merge conflict resolution required, but the existing credential is missing. Resetting state.")
            lastError = .missingLinkingInfo
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
            setState(.signedOut)
            return
        }

        setState(.authenticating("Merging accounts..."))
        lastError = nil
        do {
            let authDataResult = try await Auth.auth().signIn(with: cred)
            let user = AuthUser(firebaseUser: authDataResult.user)
            print("AuthService: Merge successful for user \(user.uid). Proceeding to check biometrics.")
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
            lastError = nil

            // Check biometrics before setting final state
            await checkBiometricsRequirement(for: user) // This will call setState internally

            print("AuthService: Merge conflict resolved. Final state: \(state)")

        } catch {
            print("AuthService ERROR: Merge sign-in failed during conflict resolution: \(error.localizedDescription)")
            lastError = AuthError.makeFirebaseAuthError(error)
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
            setState(.signedOut) // Revert to signedOut on merge failure
        }
    }

    public func cancelPendingAction() {
        print("AuthService: cancelPendingAction requested. Current State: \(state)")
        guard state.isPendingResolution else {
            print("AuthService: Cancel called but state is not pending resolution (\(state)). Ignoring request.")
            return
        }
        print("AuthService: User cancelled pending action from state: \(state)")
        setState(.signedOut)
        lastError = nil // Clear error on cancel
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
    }

    // MARK: - Private Helper Methods (@MainActor)

    private func setState(_ newState: AuthState) {
        let oldState = self.state
        if oldState == newState {
            return
        }
        print("AuthService State Change: \(oldState) -> \(newState)")
        self.state = newState
    }

    private func resetForNewSignInAttempt() {
        print("Resetting internal state for new sign-in attempt.")
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
    }

    private func clearLocalUserData() {
        Task {
            try? await secureStorage.clearLastUserID()
            print("Cleared local user data (Keychain/SecureStorage).")
        }
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
        print("Cleared Temp Creds and Email Link.")
    }

    private func performBiometricAuthentication(reason: String) async throws {
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

    // MARK: - Sign In Completion Handling

    /// Top-level handler called after firebaseAuthenticator.presentSignInUI succeeds.
    private func handleSuccessfulSignIn(user: AuthUser) async {
        print("Handling successful sign-in for user \(user.uid). Checking for pending link...")
        if let pCred = firebaseAuthenticator.pendingCredentialForLinking {
            await handleLinkingSignInCompletion(user: user, pendingCredential: pCred)
        } else {
            await handleStandardSignInCompletion(user: user)
        }
    }

    /// Handles completion for a standard sign-in or a post-merge sign-in.
    private func handleStandardSignInCompletion(user: AuthUser) async {
        print("Standard sign-in success or post-merge sign-in completed for user \(user.uid). Checking biometrics...")

        // Clear merge conflict credential if it existed (belt-and-suspenders check)
        if firebaseAuthenticator.existingCredentialForMergeConflict != nil {
            print("AuthService WARNING: Merge conflict credential present during standard sign-in completion. Clearing now.")
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
        }

        lastError = nil // Clear any previous error on this success path

        // Check biometrics requirement, which will determine and set the final state.
        await checkBiometricsRequirement(for: user)

        print("Standard sign-in process completed. Final state: \(state)")
    }

    /// Handles completion for a sign-in that requires account linking.
    private func handleLinkingSignInCompletion(user: AuthUser, pendingCredential: AuthCredential) async {
        print("Sign-in successful, now attempting account link...")
        do {
            // Perform link, which internally calls checkBiometricsRequirement on its own success.
            try await performAccountLink(loggedInUser: user, pendingCredential: pendingCredential)
            // State and lastError are set within performAccountLink
            print("Account linking process completed successfully. Final state: \(state)")
        } catch { // Catch errors from performAccountLink (already logged inside)
            // State and lastError should already be set by performAccountLink on failure.
            print("Account linking process failed. Final state: \(state), Error: \(lastError?.localizedDescription ?? "N/A")")
            // Ensure cleanup just in case performAccountLink didn't fully clean up.
            clearLocalUserData()
            // Ensure state is signedOut on any linking failure.
            if state != .signedOut {
                setState(.signedOut)
            }
        }
    }
    // --- End Sign In Completion Handling ---


    private func handleSignInAuthError(_ error: AuthError) async {
        print("AuthService: Handling Sign-In AuthError: \(error.localizedDescription)")
        lastError = error // Set the error state first

        switch error {
        case .accountLinkingRequired(let email):
            guard firebaseAuthenticator.pendingCredentialForLinking != nil else {
                print("AuthService ERROR: Account linking required error received, but pending credential missing. Resetting.")
                firebaseAuthenticator.clearTemporaryCredentials()
                emailForLinking = nil
                lastError = .missingLinkingInfo
                setState(.signedOut)
                return
            }
            self.emailForLinking = email

            do {
                let methods = try await Auth.auth().fetchSignInMethods(forEmail: email)
                print("AuthService: Existing sign-in methods for \(email): \(methods.joined(separator: ", "))")
                setState(.requiresAccountLinking(email: email, existingProviders: methods.sorted()))
            } catch let fetchError {
                print("AuthService ERROR: Fetching sign-in methods failed for \(email): \(fetchError.localizedDescription)")
                lastError = AuthError.makeFirebaseAuthError(fetchError)
                firebaseAuthenticator.clearTemporaryCredentials()
                emailForLinking = nil
                setState(.signedOut)
            }

        case .mergeConflictRequired:
            guard firebaseAuthenticator.existingCredentialForMergeConflict != nil else {
                print("AuthService ERROR: Merge conflict required error received, but existing credential missing. Resetting.")
                firebaseAuthenticator.clearTemporaryCredentials()
                emailForLinking = nil
                lastError = .missingLinkingInfo
                setState(.signedOut)
                return
            }
            setState(.requiresMergeConflictResolution)

        case .cancelled:
            if !state.isPendingResolution {
                print("AuthService: Sign-in cancelled by user. Resetting state.")
                firebaseAuthenticator.clearTemporaryCredentials()
                emailForLinking = nil
                setState(.signedOut)
            } else {
                print("AuthService: Sign-in cancelled while in pending state (\(state)). State remains.")
                // Keep lastError as .cancelled, state remains pending
            }

        default:
            print("AuthService: Unhandled sign-in error (\(error)). Resetting state.")
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
            setState(.signedOut)
        }
    }

    private func handleSignInGenericError(_ error: Error) {
        print("AuthService: Handling Generic Sign-In Error: \(error.localizedDescription)")
        lastError = AuthError.makeFirebaseAuthError(error)
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
        setState(.signedOut)
    }

    // MARK: Account Linking

    private func performAccountLink(loggedInUser: AuthUser, pendingCredential: AuthCredential) async throws {
        print("Attempting to link account for user \(loggedInUser.uid).")
        guard let fbUser = Auth.auth().currentUser, fbUser.uid == loggedInUser.uid else {
            print("AuthService ERROR: User mismatch during account link initiation. Resetting.")
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
            let specificError = AuthError.accountLinkingError("User mismatch during linking initiation.")
            lastError = specificError
            setState(.signedOut)
            throw specificError
        }

        setState(.authenticating("Linking account..."))
        lastError = nil

        do {
            let linkResult = try await fbUser.link(with: pendingCredential)
            let updatedUser = AuthUser(firebaseUser: linkResult.user)
            print("Link successful! User \(updatedUser.uid) now linked.")

            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
            lastError = nil

            // Check biometrics AFTER successful linking before setting final state
            await checkBiometricsRequirement(for: updatedUser) // Sets state internally

            print("Account linking complete. Final state after biometrics check: \(state)")

        } catch {
            print("AuthService ERROR: Account linking failed: \(error.localizedDescription)")
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil

            let nsError = error as NSError
            let specificError: AuthError
            if nsError.domain == AuthErrorDomain && nsError.code == AuthErrorCode.credentialAlreadyInUse.rawValue {
                specificError = AuthError.accountLinkingError("This sign-in method is already linked to a different account.")
            } else {
                specificError = AuthError.accountLinkingError("Failed to link account. Code: \(nsError.code), Domain: \(nsError.domain)")
            }
            lastError = specificError
            setState(.signedOut) // Revert state on linking failure
            throw specificError
        }
    }
    
    // MARK: State

    private func handleAuthStateChange(firebaseUser: FirebaseAuth.User?) async {
        guard !isTestMode else { return }

        let currentAuthServiceState = self.state

        if let fbUser = firebaseUser {
            let currentUser = AuthUser(firebaseUser: fbUser)
            print("AuthService Listener: Firebase User PRESENT (UID: \(currentUser.uid)). Current AuthService State: \(currentAuthServiceState)")

            if currentAuthServiceState.isAuthenticating && currentAuthServiceState != .requiresBiometrics {
                 print("AuthService Listener: Ignoring update because AuthService is currently authenticating: \(currentAuthServiceState)")
                 return
             }
            if currentAuthServiceState.isPendingResolution {
                print("AuthService Listener: Ignoring update because AuthService is pending user resolution: \(currentAuthServiceState)")
                return
            }

            if case .signedIn(let existingUser) = currentAuthServiceState, existingUser.uid == currentUser.uid {
                 print("AuthService Listener: State already .signedIn with correct user (\(currentUser.uid)). Re-checking biometrics requirement.")
                 await checkBiometricsRequirement(for: currentUser)
                 return
             }
            if currentAuthServiceState == .requiresBiometrics {
                 print("AuthService Listener: State is .requiresBiometrics. Re-checking biometrics requirement against current Firebase user \(currentUser.uid).")
                 await checkBiometricsRequirement(for: currentUser)
                 return
            }

            print("AuthService Listener: Firebase user present, but AuthService state was \(currentAuthServiceState). Updating state based on listener.")
            await checkBiometricsRequirement(for: currentUser)

        } else {
             // Firebase User is ABSENT (nil)
             print("AuthService Listener: Firebase User ABSENT. Current AuthService State: \(currentAuthServiceState)")

             if currentAuthServiceState != .signedOut && !currentAuthServiceState.isAuthenticating {
                 print("AuthService Listener: Firebase user became nil. Clearing local data and setting state to signedOut.")
                 clearLocalUserData()
                 lastError = nil
                 setState(.signedOut)
             } else {
                 print("AuthService Listener: Firebase user is nil, but AuthService state is already \(currentAuthServiceState). No state change needed.")
             }
         }
    }

    // --- Biometrics Check ---

    /// Determines the appropriate AuthState based on the user, stored ID, and biometrics availability.
    /// Also handles saving the user ID to secure storage if needed.
    /// - Parameter user: The non-anonymous user to check.
    /// - Returns: The calculated `AuthState` (.signedIn or .requiresBiometrics).
    private func determineBiometricState(for user: AuthUser) async -> AuthState {
        // Precondition: User should not be anonymous here.
        guard !user.isAnonymous else {
             print("AuthService Biometrics Logic ERROR: determineBiometricState called with anonymous user.")
             return .signedIn(user) // Default to signedIn for anonymous, though shouldn't happen
         }

        let lastUserID = await secureStorage.getLastUserID()
        let bioAvailable = biometricAuthenticator.isBiometricsAvailable
        print("AuthService Biometrics Logic: Checking user \(user.uid). Stored UID: \(lastUserID ?? "nil"). Bio Available: \(bioAvailable).")

        // Determine target state
        if bioAvailable && lastUserID == user.uid {
            print("AuthService Biometrics Logic: Conditions met for .requiresBiometrics.")
            return .requiresBiometrics
        } else {
            print("AuthService Biometrics Logic: Conditions met for .signedIn.")
            // Save User ID ONLY if transitioning to .signedIn state AND
            // the stored ID is different OR biometrics just became unavailable.
            if lastUserID != user.uid || !bioAvailable {
                 print("AuthService Biometrics Logic: Saving User ID \(user.uid). Reason: Stored ID='\(lastUserID ?? "nil")', BioAvailable=\(bioAvailable).")
                 do {
                     try await secureStorage.saveLastUserID(user.uid)
                     print("AuthService Biometrics Logic: User ID saved successfully.")
                 } catch {
                     // Log error but proceed with state transition
                     print("AuthService Biometrics Logic WARNING: Failed to save User ID \(user.uid) to secure storage: \(error.localizedDescription)")
                     // Consider setting a specific lastError? For now, just log.
                 }
            }
            return .signedIn(user)
        }
    }

    /// Checks if biometrics should be required for the given user and updates the service state.
    /// Called after sign-in, linking, merge resolution, or by the auth state listener.
    private func checkBiometricsRequirement(for user: AuthUser) async {
         guard !user.isAnonymous else {
             print("AuthService Biometrics Check: Skipping for anonymous user \(user.uid).")
             setState(.signedIn(user)) // Set state directly for anonymous user
             return
         }

         // Determine the required state using the helper function
         let determinedState = await determineBiometricState(for: user)

         // Update the overall service state
         setState(determinedState)
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
            self.setState(state)
        }
    #endif
}
