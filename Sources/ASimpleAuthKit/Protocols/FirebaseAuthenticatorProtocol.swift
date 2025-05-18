import Foundation
import FirebaseAuth
import UIKit

@MainActor
internal protocol FirebaseAuthenticatorProtocol {
    var pendingCredentialForLinking: AuthCredential? { get }

    func signInWithEmail(email: String, password: String) async throws -> AuthUser
    func createAccountWithEmail(email: String, password: String, displayName: String?) async throws -> AuthUser
    func signInWithGoogle(presentingViewController: UIViewController) async throws -> AuthUser
    func signInWithApple(presentingViewController: UIViewController, rawNonce: String) async throws -> AuthUser
    func sendPasswordResetEmail(to email: String) async throws

    func linkCredential(_ credentialToLink: AuthCredential, to user: FirebaseAuth.User) async throws -> AuthUser

    func clearTemporaryCredentials()
}
