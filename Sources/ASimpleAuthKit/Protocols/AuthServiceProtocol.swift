import Foundation
import Combine
import UIKit

@MainActor
public protocol AuthServiceProtocol: ObservableObject {
    var state: AuthState { get }
    var statePublisher: Published<AuthState>.Publisher { get }
    var lastError: AuthError? { get }
    var lastErrorPublisher: Published<AuthError?>.Publisher { get }

    func signIn(from viewController: UIViewController) async
    func signOut()
    func authenticateWithBiometrics(reason: String) async
    func proceedWithMergeConflictResolution() async
    func cancelPendingAction()
    
    /// **Must be called** when the AuthService instance is no longer needed
    /// to ensure proper cleanup of internal listeners (e.g., Firebase Auth state).
    /// In SwiftUI, call this from `.onDisappear` of the view owning the `@StateObject`.
    func invalidate()
}

public extension AuthServiceProtocol { // Default implementations only

    func authenticateWithBiometrics(reason: String = "Sign in to your account") async {
        await authenticateWithBiometrics(reason: reason)
    }

    func proceedWithMergeConflictResolution() async {
        print("AuthServiceProtocol: Default proceed...")
    }

    func cancelPendingAction() {
        print("AuthServiceProtocol: Default cancel...")
    }
}
