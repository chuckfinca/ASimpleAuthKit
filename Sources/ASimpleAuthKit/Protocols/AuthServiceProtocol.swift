// Sources/AuthKit/Protocols/AuthServiceProtocol.swift
import Foundation
import Combine
import UIKit

@MainActor
public protocol AuthServiceProtocol: ObservableObject {
    var state: AuthState { get }
    var statePublisher: Published<AuthState>.Publisher { get } // Provided by @Published
    var lastError: AuthError? { get }
    var lastErrorPublisher: Published<AuthError?>.Publisher { get } // Provided by @Published

    func signIn(from viewController: UIViewController) async
    func signOut()
    func authenticateWithBiometrics(reason: String) async
    func proceedWithMergeConflictResolution() async
    func cancelPendingAction()
}

public extension AuthServiceProtocol { // Default implementations only
    func authenticateWithBiometrics(reason: String = "Sign in to your account") async { await authenticateWithBiometrics(reason: reason) }
    func proceedWithMergeConflictResolution() async { print("AuthServiceProtocol: Default proceed...") }
    func cancelPendingAction() { print("AuthServiceProtocol: Default cancel...") }
}
