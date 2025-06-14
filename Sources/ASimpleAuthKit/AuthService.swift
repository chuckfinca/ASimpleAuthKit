import Foundation
import Combine
import FirebaseAuth
import UIKit

@MainActor
public class AuthService: ObservableObject, AuthServiceProtocol {

    @Published public private(set) var state: AuthState = .signedOut
    @Published public private(set) var lastError: AuthError? = nil

    public var statePublisher: Published<AuthState>.Publisher { $state }
    public var lastErrorPublisher: Published<AuthError?>.Publisher { $lastError }

    public var biometryTypeString: String {
        return biometricAuthenticator.biometryTypeString
    }

    public var isBiometricsAvailable: Bool {
        return biometricAuthenticator.isBiometricsAvailable
    }

    // Dependencies
    private let config: AuthConfig
    private let firebaseAuthenticator: FirebaseAuthenticatorProtocol
    private let biometricAuthenticator: BiometricAuthenticatorProtocol
    private let secureStorage: SecureStorageProtocol
    private let firebaseAuthClient: FirebaseAuthClientProtocol

    // Internal State
    private var authStateHandle: AuthStateDidChangeListenerHandle?
    private var cancellables = Set<AnyCancellable>()
    internal var isTestMode: Bool

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
        firebaseAuthClient: FirebaseAuthClientProtocol,
        isTestMode: Bool = false
    ) {
        self.config = config
        self.secureStorage = secureStorage
        self.firebaseAuthenticator = firebaseAuthenticator
        self.biometricAuthenticator = biometricAuthenticator
        self.firebaseAuthClient = firebaseAuthClient
        self.isTestMode = isTestMode
        print("AuthService: Initializing. Test Mode: \(isTestMode)")

        self.authStateHandle = self.firebaseAuthClient.addStateDidChangeListener { [weak self] (_, user) in
            Task { @MainActor [weak self] in
                guard let strongSelf = self else { return }
                guard !strongSelf.isTestMode else { return }
                await strongSelf.handleAuthStateChange(firebaseUser: user)
            }
        }

        // Check initial state
        Task { @MainActor [weak self] in
            guard let strongSelf = self else { return }
            guard !strongSelf.isTestMode else { return }
            await strongSelf.handleAuthStateChange(firebaseUser: strongSelf.firebaseAuthClient.currentUser)
        }
        print("AuthService: Init complete, listener added.")
    }

    // Convenience Initializer (Public - for production use)
    public convenience init(config: AuthConfig) {
        let storage = KeychainStorage(accessGroup: config.keychainAccessGroup)
        let bioAuth = BiometricAuthenticator()
        let liveFirebaseAuthClient = LiveFirebaseAuthClient()
        let fireAuth = FirebaseAuthenticator(config: config, secureStorage: storage, firebaseAuthClient: liveFirebaseAuthClient)
        self.init(
            config: config,
            secureStorage: storage,
            firebaseAuthenticator: fireAuth,
            biometricAuthenticator: bioAuth,
            firebaseAuthClient: liveFirebaseAuthClient
        )
        print("AuthService: Convenience Init completed.")
    }

    deinit {
        print("AuthService: Deinit.")
        // Since deinit is non-isolated, we must dispatch the call to invalidate()
        // back to the MainActor asynchronously.
        Task { @MainActor [weak self] in
            self?.invalidate()
        }
    }

    // MARK: - Public API - Lifecycle
    public func invalidate() {
        if let handle = authStateHandle {
            self.firebaseAuthClient.removeStateDidChangeListener(handle)
            authStateHandle = nil
            print("AuthService: Firebase Auth state listener removed via invalidate().")
        }
        cancellables.forEach { $0.cancel() }
    }

    // MARK: - Public API - Core Authentication Methods

    public func signInWithEmail(email: String, password: String) async {
        await performAuthOperation(
            authAction: {
                try await self.firebaseAuthenticator.signInWithEmail(email: email, password: password)
            },
            authActionType: .signIn
        )
    }

    public func createAccountWithEmail(email: String, password: String, displayName: String? = nil) async {
        await performAuthOperation(
            authAction: {
                try await self.firebaseAuthenticator.createAccountWithEmail(email: email, password: password, displayName: displayName)
            },
            authActionType: .signUp
        )
    }

    public func sendVerificationEmail() async {
        guard case .signedIn(let authUser) = state else {
            print("AuthService: Cannot send verification email. User not signed in.")
            return
        }

        guard let firebaseUser = self.firebaseAuthClient.currentUser else {
            print("AuthService: Cannot send verification email. No current Firebase user found.")
            return
        }

        guard firebaseUser.uid == authUser.uid else {
            print("AuthService: Mismatch between AuthService user and Firebase current user. Aborting verification email.")
            return
        }

        if firebaseUser.isEmailVerified {
            print("AuthService: Email (\(authUser.email ?? "N/A")) is already verified.")
            return
        }

        let previousState = self.state
        setState(.authenticating("Sending verification email..."))
        self.lastError = nil

        do {
            try await firebaseAuthenticator.sendEmailVerification(to: firebaseUser)
            print("AuthService: Verification email request successful for \(authUser.email ?? "N/A").")
        } catch let e as AuthError {
            print("AuthService: Failed to send verification email: \(e.localizedDescription)")
            self.lastError = e
        } catch {
            print("AuthService: Unknown error sending verification email: \(error.localizedDescription)")
            self.lastError = .unknown
        }

        setState(previousState)
    }

    public func signInWithGoogle(presentingViewController: UIViewController) async {
        await performAuthOperation(
            authAction: {
                try await self.firebaseAuthenticator.signInWithGoogle(presentingViewController: presentingViewController)
            },
            authActionType: .signIn
        )
    }

    public func signInWithApple(presentingViewController: UIViewController) async {
        let rawNonce = AuthUtilities.randomNonceString()
        await performAuthOperation(
            authAction: {
                try await self.firebaseAuthenticator.signInWithApple(presentingViewController: presentingViewController, rawNonce: rawNonce)
            },
            authActionType: .signIn
        )
    }

    public func sendPasswordResetEmail(to email: String) async {
        guard !email.isEmpty else {
            self.lastError = .configurationError("Email address cannot be empty for password reset.")
            return
        }

        let previousState = self.state
        setState(.authenticating("Sending reset email..."))
        lastError = nil

        do {
            try await firebaseAuthenticator.sendPasswordResetEmail(to: email)
            print("AuthService: Password reset email initiated for \(email).")
        } catch let e as AuthError {
            self.lastError = e
        } catch {
            self.lastError = .unknown
        }
        setState(previousState)
    }

    public func signOut() async {
        print("AuthService: signOut requested.")
        self.pendingCredentialToLinkAfterReauth = nil

        do {
            try self.firebaseAuthClient.signOut()
            print("AuthService: Firebase sign-out call successful.")
            await clearLocalUserDataAndSetSignedOutState()
            lastError = nil
            print("AuthService: State set to signedOut and local data cleared synchronously after sign out call.")
        } catch {
            print("AuthService: Sign out failed: \(error.localizedDescription)")
            lastError = AuthError.makeFirebaseAuthError(error)
            await clearLocalUserDataAndSetSignedOutState()
        }
    }


    // MARK: - Public API - Biometric Control (New Manual Control)

    public func requireBiometricAuthentication() {
        guard state == .signedOut else {
            print("AuthService: requireBiometricAuthentication called but not in .signedOut state")
            return
        }
        guard isBiometricsAvailable else {
            print("AuthService: requireBiometricAuthentication called but biometrics not available")
            return
        }
        setState(.requiresBiometrics)
    }

    public func testBiometricAuthentication() async throws {
        guard isBiometricsAvailable else {
            throw AuthError.biometricsNotAvailable
        }
        try await performBiometricAuthenticationInternal(reason: "Verify biometric authentication works")
    }

    public func authenticateWithBiometrics(reason: String = "Sign in to your account") async {
        guard state == .requiresBiometrics else {
            print("AuthService: Biometric auth requested but not in .requiresBiometrics state.")
            return
        }
        guard let currentFirebaseUser = self.firebaseAuthClient.currentUser else {
            lastError = .configurationError("Biometrics required but no Firebase user found.")
            await clearLocalUserDataAndSetSignedOutState()
            return
        }
        let uid = currentFirebaseUser.uid

        setState(.authenticating(biometricAuthenticator.biometryTypeString))
        lastError = nil
        do {
            try await performBiometricAuthenticationInternal(reason: reason)

            guard let refreshedUser = self.firebaseAuthClient.currentUser, refreshedUser.uid == uid else {
                lastError = .unknown
                await clearLocalUserDataAndSetSignedOutState()
                return
            }
            setState(.signedIn(AuthUser(firebaseUser: refreshedUser)))
        } catch let e as AuthError {
            lastError = e
            setState(.requiresBiometrics)
        } catch {
            lastError = .unknown
            setState(.requiresBiometrics)
        }
    }

    // MARK: - Public API - State Resolution Methods

    public func resolvePendingAction() {
        print("AuthService: resolvePendingAction requested. Current State: \(state)")
        guard state.isPendingResolution else {
            print("AuthService: resolvePendingAction called but state is not pending resolution (\(state)). Ignoring.")
            return
        }
        resetAuthenticationState()
        print("AuthService: Pending action resolved. State set to signedOut.")
    }

    public func resetAuthenticationState() {
        print("AuthService: resetAuthenticationState requested. Current State: \(state)")
        self.pendingCredentialToLinkAfterReauth = nil
        self.emailForLinking = nil
        firebaseAuthenticator.clearTemporaryCredentials()
        lastError = nil
        setState(.signedOut)
        print("AuthService: Authentication state completely reset to signedOut.")
    }


    // MARK: - Auth Operation Orchestration

    internal enum AuthActionType { case signIn, signUp, link }

    private func performAuthOperation(
        authAction: @escaping () async throws -> AuthUser,
        authActionType: AuthActionType
    ) async {
        let isReAuthForLinking = (self.pendingCredentialToLinkAfterReauth != nil && authActionType == .signIn)

        if !isReAuthForLinking {
            guard state.allowsSignInAttempt(for: authActionType) else {
                print("AuthService: Auth operation not allowed for current state \(state) and action type \(authActionType).")
                return
            }
            resetForNewAuthAttempt()
            setState(.authenticating(authActionType == .signUp ? "Creating Account..." : "Signing In..."))
        } else {
            setState(.authenticating("Verifying existing account..."))
        }

        do {
            let user = try await authAction()

            if let credentialToLink = self.pendingCredentialToLinkAfterReauth, isReAuthForLinking {
                print("AuthService: Re-authentication successful for linking. User: \(user.uid). Attempting to link stored credential.")
                await completeAccountLinking(loggedInUser: user, credentialToLink: credentialToLink)
            } else if self.pendingCredentialToLinkAfterReauth != nil && authActionType == .signUp {
                print("AuthService WARNING: Sign-up occurred while a link was pending. Abandoning link. New user: \(user.uid)")
                self.pendingCredentialToLinkAfterReauth = nil
                self.firebaseAuthenticator.clearTemporaryCredentials()
                await handleSuccessfulAuthentication(for: user)
            } else {
                print("AuthService: Auth operation successful. User: \(user.uid).")
                if self.pendingCredentialToLinkAfterReauth != nil {
                    print("AuthService WARNING: Auth succeeded but an unhandled pending credential existed. Clearing it now.")
                    self.pendingCredentialToLinkAfterReauth = nil
                    self.firebaseAuthenticator.clearTemporaryCredentials()
                }
                await handleSuccessfulAuthentication(for: user)
            }
        } catch let e as AuthError {
            await handleAuthOperationError(e, authActionType: authActionType, wasReAuthForLinking: isReAuthForLinking)
        } catch {
            print("AuthService: Unknown error during auth operation: \(error.localizedDescription)")
            lastError = .unknown
            if !isReAuthForLinking {
                await clearLocalUserDataAndSetSignedOutState()
            } else {
                setState(.requiresAccountLinking(email: self.emailForLinking ?? "linking email", attemptedProviderId: nil))
            }
        }
    }

    private func handleAuthOperationError(_ error: AuthError, authActionType: AuthActionType, wasReAuthForLinking: Bool = false) async {
        print("AuthService: Handling AuthError: \(error.localizedDescription) for action: \(authActionType)")
        self.lastError = error

        switch error {
        case .emailAlreadyInUseDuringCreation(let email):
            print("AuthService: Email \(email) is already in use from a creation attempt. Suggesting sign-in.")
            self.lastError = error
            self.emailForLinking = email
            self.pendingCredentialToLinkAfterReauth = nil
            setState(.emailInUseSuggestSignIn(email: email))

        case .accountLinkingRequired(let email, let attemptedProviderIdFromError):
            self.pendingCredentialToLinkAfterReauth = self.firebaseAuthenticator.pendingCredentialForLinking
            self.emailForLinking = email

            let finalAttemptedProviderId = attemptedProviderIdFromError ?? self.pendingCredentialToLinkAfterReauth?.provider

            print("AuthService: Account linking required for \(email). Attempted with provider: \(finalAttemptedProviderId ?? "unknown"). Actual pending link credential in AuthService: \(self.pendingCredentialToLinkAfterReauth != nil)")

            setState(.requiresAccountLinking(email: email, attemptedProviderId: finalAttemptedProviderId))

        case .mergeConflictError(let message):
            print("AuthService: Merge conflict error received: \(message)")
            setState(.requiresMergeConflictResolution)

        case .cancelled:
            if wasReAuthForLinking {
                print("AuthService: Re-authentication for linking cancelled. Staying in .requiresAccountLinking.")
                setState(.requiresAccountLinking(email: self.emailForLinking ?? "linking email", attemptedProviderId: self.pendingCredentialToLinkAfterReauth?.provider))
            } else {
                await clearLocalUserDataAndSetSignedOutState()
            }

        case .reauthenticationRequired:
            print("AuthService: Reauthentication required. App UI needs to handle this flow.")
            await clearLocalUserDataAndSetSignedOutState()

        default:
            if wasReAuthForLinking {
                print("AuthService: Re-authentication for linking failed with error. Staying in .requiresAccountLinking.")
                setState(.requiresAccountLinking(email: self.emailForLinking ?? "linking email", attemptedProviderId: self.pendingCredentialToLinkAfterReauth?.provider))
            } else if !state.isPendingResolution {
                await clearLocalUserDataAndSetSignedOutState()
            }
        }
    }

    // MARK: - Account Linking Specific Logic

    private func completeAccountLinking(loggedInUser: AuthUser, credentialToLink: AuthCredential) async {
        guard let firebaseUser = self.firebaseAuthClient.currentUser, firebaseUser.uid == loggedInUser.uid else {
            print("AuthService ERROR: User mismatch during account link finalization.")
            self.lastError = .accountLinkingError("User mismatch during link finalization.")
            await clearLocalUserDataAndSetSignedOutState()
            return
        }

        setState(.authenticating("Linking Account..."))

        do {
            let updatedUser = try await firebaseAuthenticator.linkCredential(credentialToLink, to: firebaseUser)
            print("AuthService: Account linking successful! Final user UID: \(updatedUser.uid)")
            self.lastError = nil
            self.pendingCredentialToLinkAfterReauth = nil
            firebaseAuthenticator.clearTemporaryCredentials()
            await handleSuccessfulAuthentication(for: updatedUser)
        } catch let e as AuthError {
            print("AuthService: Account linking failed: \(e.localizedDescription)")
            self.lastError = e
            await clearLocalUserDataAndSetSignedOutState()
        } catch {
            print("AuthService: Unknown error during account linking finalization: \(error.localizedDescription)")
            self.lastError = .unknown
            await clearLocalUserDataAndSetSignedOutState()
        }
    }

    // MARK: - Private Helper Methods

    private func handleSuccessfulAuthentication(for user: AuthUser) async {
        if !user.isAnonymous {
            do {
                try await secureStorage.saveLastUserID(user.uid)
                print("AuthService: Saved user ID \(user.uid) to secure storage.")
            } catch {
                print("AuthService: WARNING - Failed to save user ID \(user.uid) to secure storage: \(error.localizedDescription)")
            }
        }

        setState(.signedIn(user))
    }

    private func setState(_ newState: AuthState) {
        let oldState = self.state
        if oldState == newState {
            if case .requiresAccountLinking(let lEmail, let lProvider) = newState,
                case .requiresAccountLinking(let rEmail, let rProvider) = oldState {
                if lEmail == rEmail && lProvider == rProvider {
                    return
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
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
    }



    private func clearLocalUserDataAndSetSignedOutState() async {
        try? await secureStorage.clearLastUserID()
        print("AuthService: Cleared last user ID from secure storage.")
        
        if pendingCredentialToLinkAfterReauth != nil {
            pendingCredentialToLinkAfterReauth = nil
            print("AuthService: Cleared pendingCredentialToLinkAfterReauth in clearLocalUserDataAndSetSignedOutState.")
        }
        firebaseAuthenticator.clearTemporaryCredentials()
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

    // MARK: - Firebase Auth State Listener

    internal func handleAuthStateChange(firebaseUser: FirebaseAuth.User?) async {
        guard !isTestMode else {
            print("AuthService Listener: In test mode, listener ignored.")
            return
        }
        let currentAuthServiceState = self.state

        if let fbUser = firebaseUser {
            let currentUser = AuthUser(firebaseUser: fbUser)
            print("AuthService Listener: Firebase User PRESENT (UID: \(currentUser.uid)). Current AuthService State: \(currentAuthServiceState)")

            if currentAuthServiceState.isAuthenticating && currentAuthServiceState != .requiresBiometrics {
                print("AuthService Listener: Ignoring update (AuthService currently busy: \(currentAuthServiceState))")
                return
            }
            
            if currentAuthServiceState.isPendingResolution {
                print("AuthService Listener: Ignoring update (AuthService currently pending resolution: \(currentAuthServiceState))")
                return
            }

            if self.state == .signedIn(currentUser) || self.state == .requiresBiometrics {
                print("AuthService Listener: User \(currentUser.uid) already matches current state. No change needed.")
                return
            }

            print("AuthService Listener: Firebase user \(currentUser.uid) present. Current AuthService state \(self.state) is different. Setting to signedIn.")
            setState(.signedIn(currentUser))

        } else {
            print("AuthService Listener: Firebase User ABSENT. Current AuthService State: \(currentAuthServiceState)")

            if currentAuthServiceState != .signedOut && !currentAuthServiceState.isAuthenticating {
                print("AuthService Listener: Firebase user became nil. Clearing local data and setting state to signedOut.")
                await clearLocalUserDataAndSetSignedOutState()
                lastError = nil
            } else if currentAuthServiceState == .signedOut {
                print("AuthService Listener: Firebase user is nil, state is already .signedOut. No state change needed from listener.")
            } else {
                print("AuthService Listener: Firebase user is nil, but an auth operation is in progress (\(currentAuthServiceState)). Letting operation complete or fail.")
            }
        }
    }

    // MARK: - Test Helpers
    #if DEBUG
        @MainActor
        internal func forceStateForTesting(_ state: AuthState) {
            guard isTestMode else { return }
            print("AuthService (Test Mode): Forcing state to \(state)")
            self.setState(state)
        }
    #endif
}

// Extension to AuthState for allowsSignInAttempt refinement
fileprivate extension AuthState {
    func allowsSignInAttempt(for actionType: AuthService.AuthActionType) -> Bool {
        switch self {
        case .signedOut:
            return true
        case .requiresBiometrics:
            return actionType == .signIn
        case .requiresAccountLinking, .requiresMergeConflictResolution:
            return actionType == .signIn
        case .authenticating, .signedIn:
            return false
        case .emailInUseSuggestSignIn(email: _):
            return actionType == .signIn
        }
    }
}
