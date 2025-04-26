import Foundation
import FirebaseAuthUI

public struct AuthConfig {
    let providers: [FUIAuthProvider] // e.g., [FUIEmailAuth(), FUIGoogleAuth(), FUIOAuth.appleAuthProvider()]
    let tosURL: URL?
    let privacyPolicyURL: URL?
    let keychainAccessGroup: String?
    let appleUserPersister: ((_ appleUserID: String, _ firebaseUID: String) -> Void)? // Callback to persist stable Apple User ID mapping
    let appleUserRetriever: ((_ appleUserID: String) -> String?)? // Callback to retrieve Firebase UID for a given Apple User ID

    public init(
        providers: [FUIAuthProvider],
        tosURL: URL? = nil,
        privacyPolicyURL: URL? = nil,
        keychainAccessGroup: String? = nil,
        appleUserPersister: ((String, String) -> Void)? = nil,
        appleUserRetriever: ((String) -> String?)? = nil
    ) {
        self.providers = providers
        self.tosURL = tosURL
        self.privacyPolicyURL = privacyPolicyURL
        self.keychainAccessGroup = keychainAccessGroup
        self.appleUserPersister = appleUserPersister
        self.appleUserRetriever = appleUserRetriever
    }
}
