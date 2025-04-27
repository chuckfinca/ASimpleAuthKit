import Foundation
import FirebaseAuthUI

public struct AuthConfig {
    let providers: [FUIAuthProvider] // e.g., [FUIEmailAuth(), FUIGoogleAuth(), FUIOAuth.appleAuthProvider()]
    let tosURL: URL?
    let privacyPolicyURL: URL?
    let keychainAccessGroup: String?
    let appleUserPersister: ((_ appleUserID: String, _ firebaseUID: String) -> Void)? // Callback to persist stable Apple User ID mapping

    public init(
        providers: [FUIAuthProvider],
        tosURL: URL? = nil,
        privacyPolicyURL: URL? = nil,
        keychainAccessGroup: String? = nil,
        appleUserPersister: ((String, String) -> Void)? = nil
    ) {
        self.providers = providers
        self.tosURL = tosURL
        self.privacyPolicyURL = privacyPolicyURL
        self.keychainAccessGroup = keychainAccessGroup
        self.appleUserPersister = appleUserPersister
    }
}
