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

    var biometryTypeString: String { get }
    var isBiometricsAvailable: Bool { get }

    // --- Core Authentication Methods ---
    func createAccountWithEmail(email: String, password: String, displayName: String?) async
    func sendVerificationEmail() async

    func signInWithEmail(email: String, password: String) async
    func signInWithGoogle(presentingViewController: UIViewController) async
    func signInWithApple(presentingViewController: UIViewController) async
    func sendPasswordResetEmail(to email: String) async

    func signOut() async

    /// Manually puts the AuthService into .requiresBiometrics state
    /// Call this when you want to require biometric authentication
    func requireBiometricAuthentication()

    /// Tests biometric authentication without changing auth state
    /// Use this to verify biometrics work before enabling the preference
    func testBiometricAuthentication() async throws

    /// Performs biometric authentication when in .requiresBiometrics state
    func authenticateWithBiometrics(reason: String) async

    // --- State Resolution Methods ---
    func resolvePendingAction()
    func resetAuthenticationState()

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
