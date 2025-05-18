import Foundation
import Combine
import UIKit
import FirebaseAuth

@MainActor
public protocol AuthServiceProtocol: ObservableObject {
    var state: AuthState { get }
    var statePublisher: Published<AuthState>.Publisher { get }
    var lastError: AuthError? { get }
    var lastErrorPublisher: Published<AuthError?>.Publisher { get }
    var biometryTypeString: String { get } // For UI display

    // --- Core Authentication Methods ---
    func signInWithEmail(email: String, password: String) async
    func createAccountWithEmail(email: String, password: String, displayName: String?) async
    func signInWithGoogle(presentingViewController: UIViewController) async
    func signInWithApple(presentingViewController: UIViewController) async // Nonce generation handled internally by AuthService

    func signOut()
    func sendPasswordResetEmail(to email: String) async

    // --- State Resolution Methods ---
    func authenticateWithBiometrics(reason: String) async
    func cancelPendingAction()

    // --- Lifecycle ---
    func invalidate()
}

// Default implementations for convenience
public extension AuthServiceProtocol {
    func authenticateWithBiometrics(reason: String = "Sign in to your account") async {
        await authenticateWithBiometrics(reason: reason)
    }

    // Default for createAccountWithEmail without displayName
    func createAccountWithEmail(email: String, password: String) async {
        await createAccountWithEmail(email: email, password: password, displayName: nil)
    }
}
