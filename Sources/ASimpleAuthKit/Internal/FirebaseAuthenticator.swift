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
    private let firebaseAuthClient: FirebaseAuthClientProtocol

    // For Apple Sign In
    private var currentAppleSignInContinuation: CheckedContinuation<AuthUser, Error>?
    private var currentRawNonceForAppleSignIn: String?

    // For Google Sign In
    private var currentGoogleSignInContinuation: CheckedContinuation<AuthUser, Error>?

    // Stores the credential the user just attempted if Firebase returns "accountExistsWithDifferentCredential"
    private(set) var pendingCredentialForLinking: AuthCredential?

    internal init(config: AuthConfig, secureStorage: SecureStorageProtocol, firebaseAuthClient: FirebaseAuthClientProtocol) {
        self.config = config
        self.secureStorage = secureStorage
        self.firebaseAuthClient = firebaseAuthClient
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
            let authDataResult = try await self.firebaseAuthClient.signIn(withEmail: email, password: password)
            let user = AuthUser(firebaseUser: authDataResult.user)
            await handleSuccessfulAuth(for: user, fromProvider: "Email/Password")
            return user
        } catch {
            print("FirebaseAuthenticator: Email/Password sign-in failed: \(error.localizedDescription)")
            throw processFirebaseError(error, emailForContext: email)
        }
    }

    func createAccountWithEmail(email: String, password: String, displayName: String?) async throws -> AuthUser {
        print("FirebaseAuthenticator: Attempting Email/Password account creation for \(email)")
        do {
            let authDataResult = try await self.firebaseAuthClient.createUser(withEmail: email, password: password)
            if let displayName = displayName, !displayName.isEmpty {
                let changeRequest = authDataResult.user.createProfileChangeRequest()
                changeRequest.displayName = displayName
                try await changeRequest.commitChanges()
                if let updatedFirebaseUser = self.firebaseAuthClient.currentUser {
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
            throw processFirebaseError(error, emailForContext: email)
        }
    }

    func sendEmailVerification(to firebaseUser: FirebaseAuth.User) async throws {
        guard !firebaseUser.isEmailVerified else {
            print("FirebaseAuthenticator: Email for user \(firebaseUser.uid) is already verified.")
            return
        }

        print("FirebaseAuthenticator: Attempting to send email verification to user \(firebaseUser.uid) (\(firebaseUser.email ?? "N/A")).")
        do {
            try await self.firebaseAuthClient.sendEmailVerification(for: firebaseUser)
            print("FirebaseAuthenticator: Email verification sent successfully.")
        } catch {
            print("FirebaseAuthenticator: Sending email verification failed: \(error.localizedDescription)")
            throw AuthError.makeFirebaseAuthError(error)
        }
    }

    func sendPasswordResetEmail(to email: String) async throws {
        print("FirebaseAuthenticator: Sending password reset email to \(email)")
        do {
            try await self.firebaseAuthClient.sendPasswordReset(withEmail: email)
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
                        let authDataResult = try await self.firebaseAuthClient.signIn(with: credential)
                        let authUser = AuthUser(firebaseUser: authDataResult.user)
                        await self.handleSuccessfulAuth(for: authUser, fromProvider: "Google")
                        continuation.resume(returning: authUser)
                    } catch {
                        print("FirebaseAuthenticator: Firebase sign-in with Google credential failed: \(error.localizedDescription)")
                        continuation.resume(throwing: self.processFirebaseError(error, attemptedCredential: credential, emailForContext: user.profile?.email))
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

    // MARK: - ASAuthorizationControllerDelegate methods
    
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
                let authDataResult = try await self.firebaseAuthClient.signIn(with: firebaseCredential)
                let user = AuthUser(firebaseUser: authDataResult.user)

                self.config.appleUserPersister?(appleUserID, user.uid)

                await self.handleSuccessfulAuth(for: user, fromProvider: "Apple")
                continuation.resume(returning: user)
            } catch {
                print("FirebaseAuthenticator: Firebase sign-in with Apple credential failed: \(error.localizedDescription)")
                continuation.resume(throwing: self.processFirebaseError(error, attemptedCredential: firebaseCredential, emailForContext: appleIDCredential.email))
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
            let authDataResult = try await self.firebaseAuthClient.link(user: user, with: credentialToLink)
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
        self.pendingCredentialForLinking = nil
    }

    private func processFirebaseError(_ error: Error, attemptedCredential: AuthCredential? = nil, emailForContext: String? = nil) -> AuthError {
        let nsError = error as NSError
        print("FirebaseAuthenticator: Processing Firebase error - Domain: \(nsError.domain), Code: \(nsError.code), Email: \(emailForContext ?? "N/A")")

        if nsError.domain == AuthErrorDomain {
            switch nsError.code {
            case AuthErrorCode.accountExistsWithDifferentCredential.rawValue:
                let conflictingEmail: String = {
                    if let userInfoEmail = nsError.userInfo[AuthErrorUserInfoEmailKey] as? String, !userInfoEmail.isEmpty {
                        return userInfoEmail
                    }
                    if let providedEmail = emailForContext, !providedEmail.isEmpty {
                        return providedEmail
                    }
                    print("FirebaseAuthenticator: WARNING - No email available for account linking error")
                    return "Please try again"
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
                let conflictingEmail = emailForContext ?? "The provided email"
                print("FirebaseAuthenticator: Email \(conflictingEmail) already in use (from createUser).")
                self.pendingCredentialForLinking = nil
                return .emailAlreadyInUseDuringCreation(email: conflictingEmail)

            case AuthErrorCode.credentialAlreadyInUse.rawValue:
                print("FirebaseAuthenticator: Credential already in use by another account. This could be a merge conflict.")
                let message = "This sign-in method is already associated with a different user account."
                return .mergeConflictError(message)

            case AuthErrorCode.invalidCredential.rawValue:
                print("FirebaseAuthenticator: Invalid credential error - providing helpful guidance.")
                return .helpfulInvalidCredential(email: emailForContext ?? "unknown")

            case AuthErrorCode.userNotFound.rawValue:
                print("FirebaseAuthenticator: User not found - providing helpful guidance.")
                return .helpfulUserNotFound(email: emailForContext ?? "unknown")

            default:
                return AuthError.makeFirebaseAuthError(error)
            }
        }
        return AuthError.makeFirebaseAuthError(error)
    }
}
