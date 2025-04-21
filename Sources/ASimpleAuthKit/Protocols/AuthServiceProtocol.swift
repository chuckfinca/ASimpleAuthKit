import Foundation
import Combine
import UIKit // Needed for presenting UI

@MainActor
public protocol AuthServiceProtocol: ObservableObject {
    /// The current authentication state. Views observe this via @Published.
    var state: AuthState { get }

    /// Published stream of state changes.
    var statePublisher: Published<AuthState>.Publisher { get }

    /// The last error encountered during an authentication operation.
    /// UI can observe this to display error messages.
    var lastError: AuthError? { get }

    /// Published stream of error changes.
    var lastErrorPublisher: Published<AuthError?>.Publisher { get }


    /// Initiates the sign-in or sign-up flow using the configured providers.
    /// Can also be called when state is `.requiresAccountLinking` to sign in with an existing provider.
    /// Presents the necessary UI (e.g., FirebaseUI) from the provided view controller.
    /// - Parameter viewController: The view controller to present the authentication UI from.
    func signIn(from viewController: UIViewController) async

    /// Signs the current user out, clearing local session data.
    func signOut()

    /// Attempts to authenticate the user using biometrics (Face ID / Touch ID).
    /// This should typically be called when `state` is `.requiresBiometrics`.
    /// - Parameter reason: The reason string displayed to the user in the biometric prompt. Defaults to "Sign in".
    func authenticateWithBiometrics(reason: String) async

    /// Call this when the user confirms signing into the existing account during a merge conflict.
    /// This should be called when `state` is `.requiresMergeConflictResolution`.
    func proceedWithMergeConflictResolution() async

    /// Call this when the user cancels the prompt related to account linking or merge conflict.
    /// This should be called when `state` is `.requiresAccountLinking` or `.requiresMergeConflictResolution`.
    func cancelPendingAction()

    // Potentially add other methods if needed, e.g.:
    // func deleteAccount() async throws
    // func reauthenticateCurrentUser() async throws
}

// Default implementation to expose publishers easily
public extension AuthServiceProtocol {
    var statePublisher: Published<AuthState>.Publisher { $state }
    var lastErrorPublisher: Published<AuthError?>.Publisher { $lastError }

    // Add default implementations for new methods for convenience, e.g., for testing mocks
    func proceedWithMergeConflictResolution() async {}
    func cancelPendingAction() {}
    // Provide default reason for biometrics
    func authenticateWithBiometrics(reason: String = "Sign in to your account") async {
        await authenticateWithBiometrics(reason: reason)
    }
}