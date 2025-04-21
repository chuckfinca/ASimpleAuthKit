import Foundation
import FirebaseAuth
import UIKit

/// Protocol defining the interface for interacting with the Firebase Authentication UI and core logic layer.
@MainActor
internal protocol FirebaseAuthenticatorProtocol {
    /// Temporarily stored credential when account linking is required.
    var pendingCredentialForLinking: AuthCredential? { get }
    /// Temporarily stored credential when a merge conflict occurs.
    var existingCredentialForMergeConflict: AuthCredential? { get }

    /// Presents the FirebaseUI sign-in flow.
    /// - Parameter viewController: The view controller to present the UI from.
    /// - Returns: The authenticated `User`.
    /// - Throws: An `AuthError` indicating failure, cancellation, or a specific condition like `.accountLinkingRequired`.
    func presentSignInUI(from viewController: UIViewController) async throws -> User

    /// Clears any temporarily stored credentials (e.g., after resolution or cancellation).
    func clearTemporaryCredentials()
}

// Add userInfo extraction helper to AuthCredential if needed publicly, or keep internal
extension AuthCredential {
     var emailFromProviderUserInfo: String? {
         // Attempts to extract email from common provider data structures
         guard let providerID = self.providerID else { return nil }

         switch providerID {
         case GoogleAuthProviderID, FacebookAuthProviderID, EmailAuthProviderID, "apple.com": // Add others as needed
             // Firebase typically includes email in top-level userInfo for these common providers
             // Note: This relies on internal Firebase structure which *could* change, but is common practice.
             // Requires importing the specific provider SDKs usually, but here we assume userInfo exists.
             // This is a simplified example; direct access to userInfo might not be public API.
             // A more robust way involves inspecting the specific credential subclass if possible.
             // For testing purposes, we might just mock this behavior.
             // **Placeholder:** In a real scenario, you might need Firebase SDK internals or specific provider logic.
             // Let's assume for mocking it's available via a conceptual `userInfo` property.
             // return self.userInfo?["email"] as? String // Conceptual
             return nil // Return nil as direct userInfo access isn't guaranteed public API
         default:
             return nil
         }
     }
 }

 // Constants for provider IDs if not already defined elsewhere
 let GoogleAuthProviderID = "google.com"
 let FacebookAuthProviderID = "facebook.com"
 let EmailAuthProviderID = "password"
 // AppleAuthProviderID defined in FirebaseAuthenticator.swift