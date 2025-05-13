import Foundation
import UIKit

@preconcurrency import FirebaseAuth
@preconcurrency import FirebaseAuthUI

let FUIAuthErrorUserInfoEmailKey = "email"
let AppleAuthProviderID = "apple.com"

@MainActor
internal class FirebaseAuthenticator: NSObject, FUIAuthDelegate, FirebaseAuthenticatorProtocol {
    private let config: AuthConfig
    private var authUI: FUIAuth?
    private weak var presentingViewController: UIViewController?
    private var currentSignInContinuation: CheckedContinuation<AuthUser, Error>?
    private(set) var pendingCredentialForLinking: AuthCredential? // Confined to MainActor
    private(set) var existingCredentialForMergeConflict: AuthCredential? // Confined to MainActor
    private let secureStorage: SecureStorageProtocol

    init(config: AuthConfig, secureStorage: SecureStorageProtocol) {
        self.config = config
        self.secureStorage = secureStorage
        super.init()
        setupAuthUI()
    }

    private func setupAuthUI() {
        self.authUI = FUIAuth.defaultAuthUI()
        guard let authUI = self.authUI else {
            fatalError("ASimpleAuthKit Config Error: FUIAuth nil. Call FirebaseApp.configure() first.")
        }
        authUI.delegate = self
        authUI.providers = config.providers
        authUI.tosurl = config.tosURL
        authUI.privacyPolicyURL = config.privacyPolicyURL
        print("FirebaseAuthenticator: AuthUI configured.")
    }

    func clearTemporaryCredentials() {
        pendingCredentialForLinking = nil
        existingCredentialForMergeConflict = nil
        print("FirebaseAuthenticator: Cleared temporary credentials.")
    }

    func presentSignInUI(from viewController: UIViewController) async throws -> AuthUser {
        guard let authUI = self.authUI else {
            throw AuthError.configurationError("AuthUI not initialized.")
        }
        self.presentingViewController = viewController
        if let c = self.currentSignInContinuation {
            print("Auth Warning: Cancelling existing continuation.")
            self.currentSignInContinuation = nil
            c.resume(throwing: AuthError.cancelled)
        }
        print("FirebaseAuthenticator: Presenting Sign In UI from \(type(of: viewController))")

        let authVC = authUI.authViewController()
        authVC.modalPresentationStyle = .fullScreen
        return try await withCheckedThrowingContinuation {
            c in self.currentSignInContinuation = c
            viewController.present(authVC, animated: true)
        }
    }

    // MARK: - FUIAuthDelegate (nonisolated callback)
    nonisolated func authUI(_ authUI: FUIAuth, didSignInWith authDataResult: AuthDataResult?, error: Error?) {
        
        let firebaseUser = authDataResult?.user
        Task { @MainActor [weak self, firebaseUser] in // Dispatch immediately to MainActor
            guard let self = self else { return }
            guard let continuation = self.currentSignInContinuation else {
                print("Auth Warning: Delegate callback but no continuation.")
                self.presentingViewController?.dismiss(animated: true)
                return
            }

            self.currentSignInContinuation = nil // Clear immediately

            var dismissViewController = true // Assume dismissal unless linking/merge required

            if let localFirebaseUser = firebaseUser {

                // Now, interactions happen with localFirebaseUser within the MainActor context.
                let user = AuthUser(firebaseUser: localFirebaseUser) // Create Sendable User instance.
                print("FBAuth: Delegate success for \(user.uid)")

                // Perform actions needing the firebase user details
                if let appleData = localFirebaseUser.providerData.first(where: { $0.providerID == AppleAuthProviderID }) {
                    self.config.appleUserPersister?(appleData.uid, localFirebaseUser.uid)
                    print("FBAuth: Called Apple Persister.")
                }
                // Use the Sendable 'user' where appropriate
                if !user.isAnonymous {
                    try? await self.secureStorage.saveLastUserID(user.uid)
                }

                // Resume with the Sendable user struct
                continuation.resume(returning: user)

            } else if let error = error { // Process non-Sendable error on MainActor
                let nsError = error as NSError
                print("FBAuth: Delegate error: \(nsError.domain), Code: \(nsError.code)")
                var authError: AuthError // Must be Sendable

                if nsError.domain == FUIAuthErrorDomain {
                    switch nsError.code {
                    case Int(FUIAuthErrorCode.userCancelledSignIn.rawValue): // Cast for safety/consistency
                        authError = .cancelled
                        self.clearTemporaryCredentials()
                    case Int(FUIAuthErrorCode.mergeConflict.rawValue): // Cast for safety/consistency
                        guard let c = nsError.userInfo[FUIAuthCredentialKey] as? AuthCredential else {
                            authError = .missingLinkingInfo
                            break
                        }

                        self.existingCredentialForMergeConflict = c
                        authError = .mergeConflictRequired
                        dismissViewController = false
                    default: authError = .firebaseUIError("UI Error (\(nsError.code)): \(error.localizedDescription)")
                        self.clearTemporaryCredentials()
                    }

                } else if nsError.domain == AuthErrorDomain {
                    switch nsError.code {
                    case Int(AuthErrorCode.accountExistsWithDifferentCredential.rawValue):
                        guard let pendingCred = nsError.userInfo[FUIAuthCredentialKey] as? AuthCredential else {
                            authError = .missingLinkingInfo; break
                        }
                        guard let attemptedEmail = nsError.userInfo[FUIAuthErrorUserInfoEmailKey] as? String else {
                            print("FirebaseAuthenticator Error: Could not find email in accountExists error userInfo.")
                            authError = .missingLinkingInfo; break
                        }
                        self.pendingCredentialForLinking = pendingCred // Store credential
                        authError = .accountLinkingRequired(email: attemptedEmail) // Pass email
                        dismissViewController = false // Keep UI

                    case Int(AuthErrorCode.emailAlreadyInUse.rawValue):
                        // This error means the user tried to CREATE an email/password account
                        // but the email is already associated with an existing Firebase user
                        // (could be federated or another email/password user if "one account per email" is on).
                        // We don't get the password they attempted from FirebaseUI.
                        self.clearTemporaryCredentials() // Ensure no stale pending credential from other flows

                        if let emailFromError = nsError.userInfo[FUIAuthErrorUserInfoEmailKey] as? String {
                            print("FBAuth: Delegate hit emailAlreadyInUse for email: \(emailFromError). Triggering account linking guidance.")
                            // We will guide them to sign in with an existing method.
                            // If they succeed, they are just signed in. No new email/password is linked *here*
                            // because we don't have the attempted password.
                            authError = .accountLinkingRequired(email: emailFromError) // Re-use the same AuthError type.
                            // AuthService will fetch sign-in methods for this email.
                        } else {
                            print("FBAuth: Delegate hit emailAlreadyInUse but no email found in userInfo.")
                            authError = AuthError.makeFirebaseAuthError(error) // Fallback
                        }
                        // IMPORTANT: For this path, self.pendingCredentialForLinking will be nil.
                        dismissViewController = false // Keep FirebaseUI presented to show our linking prompt via CardScanView.

                    default:
                        authError = AuthError.makeFirebaseAuthError(error)
                        self.clearTemporaryCredentials()
                    }
                } else {
                    authError = AuthError.makeFirebaseAuthError(error)
                    self.clearTemporaryCredentials()
                }

                continuation.resume(throwing: authError)
                if dismissViewController { // Only dismiss if not heading to a linking/merge state
                    self.presentingViewController?.dismiss(animated: true)
                }

            } else {
                print("Auth Warning: Delegate unknown state.")
                self.clearTemporaryCredentials()
                continuation.resume(throwing: AuthError.unknown)
                self.presentingViewController?.dismiss(animated: true)
            }
        }
    }
}
