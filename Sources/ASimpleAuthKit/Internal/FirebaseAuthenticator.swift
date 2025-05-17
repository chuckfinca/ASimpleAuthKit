import Foundation
import FirebaseAuth
import FirebaseCore
import AuthenticationServices // For Sign in with Apple
import GoogleSignIn // For Google Sign-In
import GoogleSignInSwift
import UIKit // For presentingViewController

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

    // For merge conflicts (though direct API usage might change how these are encountered)
    // We might not need this if merge is always a consequence of a linking attempt with a conflict.
    // private(set) var existingCredentialForMergeConflict: AuthCredential?

    internal init(config: AuthConfig, secureStorage: SecureStorageProtocol) {
        self.config = config
        self.secureStorage = secureStorage
        super.init()
        print("FirebaseAuthenticator (Direct): Initialized.")
    }

    func clearTemporaryCredentials() {
        pendingCredentialForLinking = nil
        // existingCredentialForMergeConflict = nil
        currentRawNonceForAppleSignIn = nil // Clear nonce too
        print("FirebaseAuthenticator (Direct): Cleared temporary credentials and nonce.")
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
                // Re-fetch user to get updated profile
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

        return try await withCheckedThrowingContinuation { continuation in
            self.currentGoogleSignInContinuation = continuation
            GIDSignIn.sharedInstance.signIn(withPresenting: presentingViewController, hint: nil, additionalScopes: nil) { [weak self] result, error in
                guard let self = self else {
                    continuation.resume(throwing: AuthError.unknown)
                    return
                }
                self.currentGoogleSignInContinuation = nil // Clear continuation

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
                
                Task { @MainActor in // Ensure Firebase auth runs on MainActor
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
        self.currentRawNonceForAppleSignIn = rawNonce // Store raw nonce for use in delegate
        let hashedNonce = AuthUtilities.sha256(rawNonce)

        let appleIDProvider = ASAuthorizationAppleIDProvider()
        let request = appleIDProvider.createRequest()
        request.requestedScopes = [.fullName, .email]
        request.nonce = hashedNonce

        let authorizationController = ASAuthorizationController(authorizationRequests: [request])
        authorizationController.delegate = self
        authorizationController.presentationContextProvider = self // `self` provides the window
        
        // Store the continuation to be resumed by the delegate
        return try await withCheckedThrowingContinuation { continuation in
            self.currentAppleSignInContinuation = continuation
            authorizationController.performRequests() // This presents the Apple Sign-In UI
        }
    }

    // ASAuthorizationControllerDelegate methods
    nonisolated public func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        Task { @MainActor [weak self] in // Switch to MainActor
            guard let self = self else { return }
            guard let continuation = self.currentAppleSignInContinuation else {
                print("FirebaseAuthenticator: Apple Sign-In - No continuation found.")
                return
            }
            self.currentAppleSignInContinuation = nil // Clear immediately

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
            self.currentRawNonceForAppleSignIn = nil // Clear after use

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
                fullName: appleIDCredential.fullName // Can be nil after first sign-in
            )
            
            // Stable Apple User ID
            let appleUserID = appleIDCredential.user

            do {
                let authDataResult = try await Auth.auth().signIn(with: firebaseCredential)
                let user = AuthUser(firebaseUser: authDataResult.user)
                
                // Persist Apple User ID mapping if configured
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
        Task { @MainActor [weak self] in // Switch to MainActor
            guard let self = self else { return }
            guard let continuation = self.currentAppleSignInContinuation else {
                print("FirebaseAuthenticator: Apple Sign-In (Error) - No continuation found.")
                return
            }
            self.currentAppleSignInContinuation = nil // Clear immediately
            self.currentRawNonceForAppleSignIn = nil  // Clear nonce

            let nsError = error as NSError
            if nsError.domain == ASAuthorizationErrorDomain && nsError.code == ASAuthorizationError.canceled.rawValue {
                print("FirebaseAuthenticator: Apple Sign-In cancelled by user.")
                continuation.resume(throwing: AuthError.cancelled)
            } else {
                print("FirebaseAuthenticator: Apple Sign-In failed: \(error.localizedDescription)")
                continuation.resume(throwing: AuthError.makeProviderSpecificError(provider: "Apple", error: error))
            }
        }
    }

    // ASAuthorizationControllerPresentationContextProviding
    public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        // This needs to return the window of the presenting view controller.
        // The app side should pass the UIWindow if possible, or we find it.
        // For now, let's assume we can get it from a passed-in view controller indirectly.
        // This part is tricky without direct access to the presentingViewController's window.
        // The caller (AuthService) will have the VC.
        // This needs careful handling if the VC is not yet in the window hierarchy.
        guard let keyWindow = UIApplication.shared.connectedScenes
            .filter({$0.activationState == .foregroundActive})
            .map({$0 as? UIWindowScene})
            .compactMap({$0})
            .first?.windows
            .filter({$0.isKeyWindow}).first else {
                // Fallback or error, though this should ideally always be available
                // when Apple Sign In is triggered.
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
            // After successful linking, the new provider is part of the user.
            // No specific provider string here as it's a generic link.
            await handleSuccessfulAuth(for: updatedUser, fromProvider: "Link (\(credentialToLink.provider))")
            return updatedUser
        } catch {
            print("FirebaseAuthenticator: Linking credential failed: \(error.localizedDescription)")
            // If linking fails because the credential is ALREADY in use by ANOTHER account,
            // this is AuthErrorCode.credentialAlreadyInUse.
            // This is a more complex scenario - potentially a merge situation or just a hard stop.
            throw processFirebaseError(error) // Let AuthService decide next steps based on this error
        }
    }

    // MARK: - Common Helpers

    private func handleSuccessfulAuth(for user: AuthUser, fromProvider: String) async {
        print("FirebaseAuthenticator: Successfully authenticated user \(user.uid) via \(fromProvider).")
        // Clear any pending linking credential as sign-in was successful
        self.pendingCredentialForLinking = nil
        if !user.isAnonymous {
            do {
                try await secureStorage.saveLastUserID(user.uid)
                print("FirebaseAuthenticator: Saved user ID \(user.uid) to secure storage.")
            } catch {
                print("FirebaseAuthenticator: WARNING - Failed to save user ID \(user.uid) to secure storage: \(error.localizedDescription)")
                // Non-fatal, app can continue.
            }
        }
    }

    private func processFirebaseError(_ error: Error, attemptedCredential: AuthCredential? = nil, email: String? = nil) -> AuthError {
        let nsError = error as NSError
        print("FirebaseAuthenticator: Processing Firebase error - Domain: \(nsError.domain), Code: \(nsError.code), Email: \(email ?? "N/A")")

        if nsError.domain == AuthErrorDomain {
            switch nsError.code {
            case AuthErrorCode.accountExistsWithDifferentCredential.rawValue:
                // This means the user tried to SIGN IN (e.g. with Google) but the email
                // is already associated with an existing Firebase user (e.g. via Apple).
                // The `attemptedCredential` is the one they just tried (Google in this example).
                // The `nsError.userInfo[AuthErrorUserInfoUpdatedCredentialKey]` might also contain this.
                // The `nsError.userInfo[AuthErrorUserInfoEmailKey]` contains the conflicting email.
                let conflictingEmail = nsError.userInfo[AuthErrorUserInfoEmailKey] as? String ?? email ?? "unknown"
                let newCredential = nsError.userInfo[AuthErrorUserInfoUpdatedCredentialKey] as? AuthCredential ?? attemptedCredential

                if let cred = newCredential {
                    self.pendingCredentialForLinking = cred // Store it for AuthService to use
                    print("FirebaseAuthenticator: Stored pending credential for linking. Provider: \(cred.provider)")
                    return .accountLinkingRequired(email: conflictingEmail, pendingCredential: cred)
                } else {
                    print("FirebaseAuthenticator: Error - accountExistsWithDifferentCredential but no credential found in error/attempt.")
                    return .missingLinkingInfo // Should not happen if `attemptedCredential` was passed
                }

            case AuthErrorCode.emailAlreadyInUse.rawValue:
                // This means the user tried to CREATE an Email/Password account, but the email
                // is already in use (could be by any provider, including another Email/Password).
                let conflictingEmail = nsError.userInfo[AuthErrorUserInfoEmailKey] as? String ?? email ?? "unknown"
                print("FirebaseAuthenticator: Email \(conflictingEmail) already in use. Suggesting linking.")
                // No `pendingCredential` here because we don't have the password they typed to form one.
                // AuthService will guide them to sign in with an existing method.
                self.pendingCredentialForLinking = nil // Ensure it's nil
                return .accountLinkingRequired(email: conflictingEmail, pendingCredential: nil)

            case AuthErrorCode.credentialAlreadyInUse.rawValue:
                 // This error is nuanced. It can happen if:
                 // 1. You try to LINK a credential (e.g. Google) to User A, but that Google account
                 //    is ALREADY linked to a *different* Firebase User B. This is a hard stop/merge scenario.
                 // 2. Sometimes, it might appear if you try to sign-in with a credential that is already
                 //    linked to the *current* user, but this is less common and usually a success.
                 print("FirebaseAuthenticator: Credential already in use by another account.")
                 // This is a tricky one. For now, map it to a generic firebaseAuthError.
                 // AuthService might need more sophisticated logic if it wants to handle potential merges.
                 // For now, the linking will fail, and this error will be shown.
                 // A more advanced system might try to detect if this implies a merge is possible.
                return AuthError.firebaseAuthError(FirebaseErrorData(code: nsError.code, domain: nsError.domain, message: "This sign-in method is already associated with a different user account."))


            default:
                return AuthError.makeFirebaseAuthError(error)
            }
        }
        return AuthError.makeFirebaseAuthError(error) // Fallback for other domains
    }
}
