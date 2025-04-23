// Sources/AuthKit/Protocols/FirebaseAuthenticatorProtocol.swift
import Foundation
import FirebaseAuth
import UIKit

@MainActor
internal protocol FirebaseAuthenticatorProtocol {
    var pendingCredentialForLinking: AuthCredential? { get } // Access ONLY on MainActor
    var existingCredentialForMergeConflict: AuthCredential? { get } // Access ONLY on MainActor

    func presentSignInUI(from viewController: UIViewController) async throws -> User // Returns Sendable
    func clearTemporaryCredentials() // Call ONLY on MainActor
}
