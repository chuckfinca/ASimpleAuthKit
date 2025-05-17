import Foundation
import Combine
import UIKit // For presentingViewController in some auth methods
import FirebaseAuth // For AuthCredential (exposed if AuthError case includes it)

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
    func proceedWithAccountLink(signInAgainWithProvider: @escaping (UIViewController) async throws -> AuthUser) async // More abstract linking
    func proceedWithMergeConflictResolution() async // This might be re-evaluated based on how merge conflicts surface now
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

    // Default proceedWithMergeConflictResolution might just log if not implemented specifically
    func proceedWithMergeConflictResolution() async {
        print("AuthServiceProtocol: Default proceedWithMergeConflictResolution called. Ensure specific implementation if needed.")
    }

    // Default cancelPendingAction is already provided in your original file, can be kept or removed if not desired
    // func cancelPendingAction() {
    //     print("AuthServiceProtocol: Default cancelPendingAction called.")
    // }
}