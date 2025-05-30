import Foundation
import FirebaseAuth
import FirebaseCore
import AuthenticationServices
import GoogleSignIn
import GoogleSignInSwift
import UIKit

@MainActor
internal class FirebaseAuthenticator: NSObject, FirebaseAuthenticatorProtocol, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {

    private let config: AuthConfig
    private let secureStorage: SecureStorageProtocol

    // For Apple Sign In
    private var currentAppleSignInContinuation: CheckedContinuation<AuthUser, Error>?
    private var currentRawNonceForAppleSignIn: String?

    // For Google Sign In
    private var currentGoogleSignInContinuation: CheckedContinuation<AuthUser, Error>?

    // Stores the credential the user just attempted if Firebase returns "accountExistsWithDifferentCredential"
    private(set) var pendingCredentialForLinking: AuthCredential?

    internal init(config: AuthConfig, secureStorage: SecureStorageProtocol) {
        self.config = config
        self.secureStorage = secureStorage
        super.init()
        print("FirebaseAuthenticator: Initialized.")
    }

    func clearTemporaryCredentials() {
        pendingCredentialForLinking = nil
        currentRawNonceForAppleSignIn = nil
        print("FirebaseAuthenticator: Cleared temporary credentials and nonce.")
    }

    // MARK: - Email/Password Authentication

    func signInWithEmail(email: String, password: String) async throws -> AuthUser {
        print("FirebaseAuthenticator: Attempting Email/Password sign-in for \(email)")
        do {
            let authDataResult = try await Auth.auth().signIn(withEmail: email, password: password)
            let user = AuthUser(firebaseUser: authDataResult.user)
            await handleSuccessfulAuth(for: user, fromProvider: "Email/Password")
            return user
        } catch {
            print("FirebaseAuthenticator: Email/Password sign-in failed: \(error.localizedDescription)")
            throw processFirebaseError(error)
        }
    }

    func createAccountWithEmail(email: String, password: String, displayName: String?) async throws -> AuthUser {
        print("FirebaseAuthenticator: Attempting Email/Password account creation for \(email)")
        do {
            let authDataResult = try await Auth.auth().createUser(withEmail: email, password: password)
            if let displayName = displayName, !displayName.isEmpty {
                let changeRequest = authDataResult.user.createProfileChangeRequest()
                changeRequest.displayName = displayName
                try await changeRequest.commitChanges()
                if let updatedFirebaseUser = Auth.auth().currentUser {
                    let user = AuthUser(firebaseUser: updatedFirebaseUser)
                    await handleSuccessfulAuth(for: user, fromProvider: "Email/Password (Create)")
                    return user
                }
            }
            let user = AuthUser(firebaseUser: authDataResult.user)
            await handleSuccessfulAuth(for: user, fromProvider: "Email/Password (Create)")
            return user
        } catch {
            print("FirebaseAuthenticator: Email/Password account creation failed: \(error.localizedDescription)")
            throw processFirebaseError(error)
        }
    }

    func sendPasswordResetEmail(to email: String) async throws {
        print("FirebaseAuthenticator: Sending password reset email to \(email)")
        do {
            try await Auth.auth().sendPasswordReset(withEmail: email)
            print("FirebaseAuthenticator: Password reset email sent successfully.")
        } catch {
            print("FirebaseAuthenticator: Sending password reset email failed: \(error.localizedDescription)")
            throw processFirebaseError(error)
        }
    }

    // MARK: - Google Sign-In

    func signInWithGoogle(presentingViewController: UIViewController) async throws -> AuthUser {
        print("FirebaseAuthenticator: Attempting Google sign-in.")

        guard let clientID = FirebaseApp.app()?.options.clientID else {
            print("FirebaseAuthenticator: Google Sign-In error - Firebase Client ID not found.")
            throw AuthError.configurationError("Google Sign-In: Firebase Client ID missing.")
        }

        let currentConfig = GIDSignIn.sharedInstance.configuration
        if currentConfig == nil || currentConfig?.clientID != clientID {
            print("FirebaseAuthenticator: Configuring Google Sign-In with client ID from Firebase.")
            GIDSignIn.sharedInstance.configuration = GIDConfiguration(clientID: clientID)
        }

        return try await withCheckedThrowingContinuation { continuation in
            self.currentGoogleSignInContinuation = continuation
            GIDSignIn.sharedInstance.signIn(withPresenting: presentingViewController, hint: nil, additionalScopes: nil) { [weak self] result, error in
                guard let self = self else {
                    continuation.resume(throwing: AuthError.unknown)
                    return
                }
                self.currentGoogleSignInContinuation = nil

                if let error = error {
                    print("FirebaseAuthenticator: GoogleSignIn SDK error: \(error.localizedDescription)")
                    continuation.resume(throwing: AuthError.makeProviderSpecificError(provider: "Google", error: error))
                    return
                }
                guard let user = result?.user, let idToken = user.idToken?.tokenString else {
                    print("FirebaseAuthenticator: GoogleSignIn - ID token or user missing.")
                    continuation.resume(throwing: AuthError.providerSpecificError(provider: "Google", underlyingError: nil))
                    return
                }

                let credential = GoogleAuthProvider.credential(withIDToken: idToken,
                                                               accessToken: user.accessToken.tokenString)

                Task { @MainActor in
                    do {
                        let authDataResult = try await Auth.auth().signIn(with: credential)
                        let authUser = AuthUser(firebaseUser: authDataResult.user)
                        await self.handleSuccessfulAuth(for: authUser, fromProvider: "Google")
                        continuation.resume(returning: authUser)
                    } catch {
                        print("FirebaseAuthenticator: Firebase sign-in with Google credential failed: \(error.localizedDescription)")
                        continuation.resume(throwing: self.processFirebaseError(error, attemptedCredential: credential, email: user.profile?.email))
                    }
                }
            }
        }
    }

    // MARK: - Sign in with Apple

    func signInWithApple(presentingViewController: UIViewController, rawNonce: String) async throws -> AuthUser {
        print("FirebaseAuthenticator: Attempting Sign in with Apple.")
        self.currentRawNonceForAppleSignIn = rawNonce
        let hashedNonce = AuthUtilities.sha256(rawNonce)

        let appleIDProvider = ASAuthorizationAppleIDProvider()
        let request = appleIDProvider.createRequest()
        request.requestedScopes = [.fullName, .email]
        request.nonce = hashedNonce

        let authorizationController = ASAuthorizationController(authorizationRequests: [request])
        authorizationController.delegate = self
        authorizationController.presentationContextProvider = self

        return try await withCheckedThrowingContinuation { continuation in
            self.currentAppleSignInContinuation = continuation
            authorizationController.performRequests()
        }
    }

    // ASAuthorizationControllerDelegate methods
    nonisolated public func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {

        Task { @MainActor [weak self] in
            guard let self = self else { return }
            guard let continuation = self.currentAppleSignInContinuation else {
                print("FirebaseAuthenticator: Apple Sign-In - No continuation found.")
                return
            }
            self.currentAppleSignInContinuation = nil

            guard let appleIDCredential = authorization.credential as? ASAuthorizationAppleIDCredential else {
                print("FirebaseAuthenticator: Apple Sign-In - Invalid Apple ID credential.")
                continuation.resume(throwing: AuthError.providerSpecificError(provider: "Apple", underlyingError: nil))
                return
            }

            guard let rawNonce = self.currentRawNonceForAppleSignIn else {
                print("FirebaseAuthenticator: Apple Sign-In - Raw nonce missing.")
                continuation.resume(throwing: AuthError.configurationError("Apple Sign-In: Nonce missing."))
                return
            }
            self.currentRawNonceForAppleSignIn = nil

            guard let appleIDToken = appleIDCredential.identityToken else {
                print("FirebaseAuthenticator: Apple Sign-In - ID token missing.")
                continuation.resume(throwing: AuthError.providerSpecificError(provider: "Apple", underlyingError: nil))
                return
            }
            guard let idTokenString = String(data: appleIDToken, encoding: .utf8) else {
                print("FirebaseAuthenticator: Apple Sign-In - Could not convert ID token to string.")
                continuation.resume(throwing: AuthError.providerSpecificError(provider: "Apple", underlyingError: nil))
                return
            }

            let firebaseCredential = OAuthProvider.appleCredential(
                withIDToken: idTokenString,
                rawNonce: rawNonce,
                fullName: appleIDCredential.fullName
            )

            let appleUserID = appleIDCredential.user

            do {
                let authDataResult = try await Auth.auth().signIn(with: firebaseCredential)
                let user = AuthUser(firebaseUser: authDataResult.user)

                self.config.appleUserPersister?(appleUserID, user.uid)

                await self.handleSuccessfulAuth(for: user, fromProvider: "Apple")
                continuation.resume(returning: user)
            } catch {
                print("FirebaseAuthenticator: Firebase sign-in with Apple credential failed: \(error.localizedDescription)")
                continuation.resume(throwing: self.processFirebaseError(error, attemptedCredential: firebaseCredential, email: appleIDCredential.email))
            }
        }
    }

    nonisolated public func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        Task { @MainActor [weak self] in
            guard let self = self else { return }
            guard let continuation = self.currentAppleSignInContinuation else {
                print("FirebaseAuthenticator: Apple Sign-In (Error) - No continuation found.")
                return
            }
            self.currentAppleSignInContinuation = nil
            self.currentRawNonceForAppleSignIn = nil

            print("FirebaseAuthenticator: Apple Sign-In failed: \(error.localizedDescription)")
            continuation.resume(throwing: AuthError.makeProviderSpecificError(provider: "Apple", error: error))
        }
    }

    public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        guard let keyWindow = UIApplication.shared.connectedScenes
            .filter({ $0.activationState == .foregroundActive })
            .map({ $0 as? UIWindowScene })
            .compactMap({ $0 })
            .first?.windows
            .filter({ $0.isKeyWindow }).first else {
            fatalError("ASimpleAuthKit: Could not find key window for Apple Sign In presentation.")
        }
        return keyWindow
    }

    // MARK: - Account Linking

    func linkCredential(_ credentialToLink: AuthCredential, to user: FirebaseAuth.User) async throws -> AuthUser {
        print("FirebaseAuthenticator: Attempting to link new credential to user \(user.uid)")
        do {
            let authDataResult = try await user.link(with: credentialToLink)
            let updatedUser = AuthUser(firebaseUser: authDataResult.user)
            await handleSuccessfulAuth(for: updatedUser, fromProvider: "Link (\(credentialToLink.provider))")
            return updatedUser
        } catch {
            print("FirebaseAuthenticator: Linking credential failed: \(error.localizedDescription)")
            throw processFirebaseError(error)
        }
    }

    // MARK: - Common Helpers

    private func handleSuccessfulAuth(for user: AuthUser, fromProvider: String) async {
        print("FirebaseAuthenticator: Successfully authenticated user \(user.uid) via \(fromProvider).")
        // Clear any pending linking credential as sign-in was successful
        self.pendingCredentialForLinking = nil
        
        // NOTE: Removed automatic user ID saving - AuthService now handles this (Option B approach)
        // The AuthService will save the user ID after successful authentication
    }

    private func processFirebaseError(_ error: Error, attemptedCredential: AuthCredential? = nil, email: String? = nil) -> AuthError {
        let nsError = error as NSError
        print("FirebaseAuthenticator: Processing Firebase error - Domain: \(nsError.domain), Code: \(nsError.code), Email: \(email ?? "N/A")")

        if nsError.domain == AuthErrorDomain {
            switch nsError.code {
            case AuthErrorCode.accountExistsWithDifferentCredential.rawValue:
                // Try multiple sources for the email, prefer non-empty values
                let conflictingEmail: String = {
                    if let userInfoEmail = nsError.userInfo[AuthErrorUserInfoEmailKey] as? String, !userInfoEmail.isEmpty {
                        return userInfoEmail
                    }
                    if let providedEmail = email, !providedEmail.isEmpty {
                        return providedEmail
                    }
                    // If we still don't have an email, this is a configuration issue
                    print("FirebaseAuthenticator: WARNING - No email available for account linking error")
                    return "Please try again" // More user-friendly than "unknown"
                }()
                
                let credentialToStoreForLinking = nsError.userInfo[AuthErrorUserInfoUpdatedCredentialKey] as? AuthCredential ?? attemptedCredential

                if let cred = credentialToStoreForLinking {
                    self.pendingCredentialForLinking = cred
                    print("FirebaseAuthenticator: Stored pending credential for linking. Provider: \(cred.provider)")
                    return .accountLinkingRequired(email: conflictingEmail, attemptedProviderId: cred.provider)
                } else {
                    print("FirebaseAuthenticator: Error - accountExistsWithDifferentCredential but no credential found in error/attempt.")
                    return .missingLinkingInfo
                }

            case AuthErrorCode.emailAlreadyInUse.rawValue:
                let conflictingEmail: String = {
                    if let userInfoEmail = nsError.userInfo[AuthErrorUserInfoEmailKey] as? String, !userInfoEmail.isEmpty {
                        return userInfoEmail
                    }
                    if let providedEmail = email, !providedEmail.isEmpty {
                        return providedEmail
                    }
                    return "Please try again"
                }()
                
                print("FirebaseAuthenticator: Email \(conflictingEmail) already in use (likely from create user). Suggesting linking.")
                self.pendingCredentialForLinking = nil
                return .accountLinkingRequired(email: conflictingEmail, attemptedProviderId: attemptedCredential?.provider)


            case AuthErrorCode.credentialAlreadyInUse.rawValue:
                print("FirebaseAuthenticator: Credential already in use by another account. This could be a merge conflict.")
                let message = "This sign-in method is already associated with a different user account. Please sign in with that account if you wish to merge, or contact support."
                return .mergeConflictError(message)

            case AuthErrorCode.invalidCredential.rawValue:
                print("FirebaseAuthenticator: Invalid credential error - providing helpful guidance.")
                return .helpfulInvalidCredential(email: email ?? "unknown")

            case AuthErrorCode.userNotFound.rawValue:
                print("FirebaseAuthenticator: User not found - providing helpful guidance.")
                return .helpfulUserNotFound(email: email ?? "unknown")

            default:
                return AuthError.makeFirebaseAuthError(error)
            }
        }
        return AuthError.makeFirebaseAuthError(error)
    }
}
