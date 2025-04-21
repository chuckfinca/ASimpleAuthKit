import Foundation
import FirebaseAuth
import FirebaseAuthUI

@MainActor
internal class FirebaseAuthenticator: NSObject, FUIAuthDelegate {
    private let config: AuthConfig
    private var authUI: FUIAuth?
    private weak var presentingViewController: UIViewController?
    private var currentSignInContinuation: CheckedContinuation<User, Error>?

    // Store credentials temporarily when linking/merge is required
    private(set) var pendingCredentialForLinking: AuthCredential?
    private(set) var existingCredentialForMergeConflict: AuthCredential?

    private let secureStorage: SecureStorageProtocol // Keep for saving user ID on success

    init(config: AuthConfig, secureStorage: SecureStorageProtocol) {
        self.config = config
        self.secureStorage = secureStorage
        super.init()
        setupAuthUI()
    }

    private func setupAuthUI() {
        self.authUI = FUIAuth.defaultAuthUI()
        guard let authUI = self.authUI else {
            print("AuthKit Configuration Error: FUIAuth.defaultAuthUI() is nil. Ensure FirebaseApp.configure() is called first.")
            // Consider throwing or handling this more gracefully
            return
        }
        authUI.delegate = self
        authUI.providers = config.providers
        authUI.tosurl = config.tosURL
        authUI.privacyPolicyURL = config.privacyPolicyURL
        // Enable anonymous user upgrade handling if needed by config
        // authUI.shouldAutoUpgradeAnonymousUsers = config.enableAnonymousUpgrade ?? false
        print("FirebaseAuthenticator: AuthUI configured with providers: \(config.providers.map { $0.providerID! }.joined(separator: ", "))")
    }

    /// Clears any temporarily stored credentials.
    func clearTemporaryCredentials() {
        pendingCredentialForLinking = nil
        existingCredentialForMergeConflict = nil
        print("FirebaseAuthenticator: Cleared temporary credentials.")
    }

    /// Presents the FirebaseUI sign-in flow.
    func presentSignInUI(from viewController: UIViewController) async throws -> User {
        guard let authUI = self.authUI else { throw AuthError.configurationError("AuthUI not initialized") }
        self.presentingViewController = viewController
        // Ensure clean state before starting a *potentially new* full flow
        // Let AuthService decide when to clear based on the overall flow state.
        // clearTemporaryCredentials()

        // Ensure no previous continuation is active
        if currentSignInContinuation != nil {
            print("FirebaseAuthenticator Warning: Overwriting an existing sign-in continuation.")
            currentSignInContinuation?.resume(throwing: AuthError.cancelled) // Cancel previous one
        }

        print("FirebaseAuthenticator: Presenting Sign In UI from \(type(of: viewController))")
        return try await withCheckedThrowingContinuation { continuation in
            self.currentSignInContinuation = continuation
            let authViewController = authUI.authViewController()
            authViewController.modalPresentationStyle = .fullScreen
            viewController.present(authViewController, animated: true)
        }
    }

    // MARK: - FUIAuthDelegate Methods

    nonisolated func authUI(_ authUI: FUIAuth, didSignInWith authDataResult: AuthDataResult?, error: Error?) {
        // Dispatch to Main Actor for UI work and state updates
        Task { @MainActor [weak self] in
            guard let self = self else { return }
            print("FirebaseAuthenticator: Received FUIAuthDelegate callback.")
            guard let continuation = currentSignInContinuation else {
                print("FirebaseAuthenticator Warning: AuthUI callback received but no continuation stored. Dismissing UI.")
                presentingViewController?.dismiss(animated: true)
                return
            }
            // IMPORTANT: Clear continuation immediately after capturing it to prevent reuse/leaks
            self.currentSignInContinuation = nil

            if let userResult = authDataResult?.user {
                let user = User(firebaseUser: userResult)
                print("FirebaseAuthenticator: Delegate success for user \(user.uid)")

                // Persist Apple User ID mapping if needed
                if let appleProviderData = userResult.providerData.first(where: { $0.providerID == AppleAuthProviderID }) {
                    let stableAppleUserID = appleProviderData.uid
                    config.appleUserPersister?(stableAppleUserID, userResult.uid)
                    print("FirebaseAuthenticator: Called Apple User Persister for ID \(stableAppleUserID)")
                }

                // Save this successful user for biometric check next time (only if not anonymous?)
                if !user.isAnonymous {
                    try? secureStorage.saveLastUserID(user.uid)
                }

                // Do NOT clear temporary credentials here yet. AuthService needs them
                // if this sign-in was part of a linking flow.
                // clearTemporaryCredentials()

                continuation.resume(returning: user)
                // Let AuthService handle dismissing after potential linking
                // presentingViewController?.dismiss(animated: true)

            } else if let nsError = error as NSError? {
                print("FirebaseAuthenticator: Delegate received error: \(nsError.domain), code: \(nsError.code), desc: \(nsError.localizedDescription)")
                // --- Handle Specific Firebase Auth Errors ---
                if nsError.code == AuthErrorCode.accountExistsWithDifferentCredential.rawValue {
                    print("FirebaseAuthenticator: Detected AccountExistsWithDifferentCredential.")
                    guard let pendingCred = nsError.userInfo[FUIAuthCredentialKey] as? AuthCredential else {
                        continuation.resume(throwing: AuthError.missingLinkingInfo)
                        // Dismiss here as the flow cannot proceed
                        presentingViewController?.dismiss(animated: true)
                        return
                    }
                    // Store the credential and signal the required state via error
                    print("FirebaseAuthenticator: Storing pending credential for linking.")
                    self.pendingCredentialForLinking = pendingCred
                    continuation.resume(throwing: AuthError.accountLinkingRequired)
                    // Don't dismiss UI - AuthService needs to change state first

                } else if nsError.code == FUIAuthErrorCode.mergeConflict.rawValue {
                    print("FirebaseAuthenticator: Detected MergeConflict.")
                    guard let existingCred = nsError.userInfo[FUIAuthCredentialKey] as? AuthCredential else {
                        continuation.resume(throwing: AuthError.missingLinkingInfo)
                        presentingViewController?.dismiss(animated: true)
                        return
                    }
                    // Store the credential and signal the required state via error
                    print("FirebaseAuthenticator: Storing existing credential for merge conflict.")
                    self.existingCredentialForMergeConflict = existingCred
                    continuation.resume(throwing: AuthError.mergeConflictRequired)
                    // Don't dismiss UI

                    // --- Handle FirebaseUI Specific Errors ---
                } else if nsError.code == FUIAuthErrorCode.userCancelledSignIn.rawValue {
                    print("FirebaseAuthenticator: Detected User Cancelled.")
                    clearTemporaryCredentials() // Clear temps on cancellation
                    continuation.resume(throwing: AuthError.cancelled)
                    presentingViewController?.dismiss(animated: true)

                    // --- Handle Other Errors ---
                } else {
                    print("FirebaseAuthenticator: Detected other FirebaseAuth error.")
                    clearTemporaryCredentials() // Clear temps on other errors
                    // Wrap the original error
                    continuation.resume(throwing: AuthError.firebaseAuthError(error!))
                    presentingViewController?.dismiss(animated: true)
                }
            } else {
                // Unknown state
                print("FirebaseAuthenticator Warning: Delegate received neither user nor error.")
                clearTemporaryCredentials()
                continuation.resume(throwing: AuthError.unknown)
                presentingViewController?.dismiss(animated: true)
            }
        }
    }

    // Required delegate method for Apple Sign In presentation anchor
    #if !os(macOS) && !targetEnvironment(macCatalyst)
        @available(iOS 13.0, *)
        func presentationAnchor(for controller: FUIAuth) -> UIWindow {
            print("FirebaseAuthenticator: Providing presentation anchor.")
            guard let window = presentingViewController?.view.window else {
                print("FirebaseAuthenticator Error: Could not find presenting view controller's window for Apple Sign In. Falling back to key window.")
                // Attempting a more robust fallback
                let fallbackWindow = UIApplication.shared.connectedScenes
                    .compactMap { $0 as? UIWindowScene }
                    .first { $0.activationState == .foregroundActive }?
                    .windows
                    .first(where: \.isKeyWindow)
                    ?? UIApplication.shared.windows.first // Absolute fallback

                guard let validWindow = fallbackWindow else {
                    // This should realistically never happen in a running app
                    fatalError("AuthKit Fatal Error: Could not find any window for Apple Sign In presentation.")
                }
                return validWindow
            }
            return window
        }
    #endif
}

// Helper constant for provider ID
let AppleAuthProviderID = "apple.com"

