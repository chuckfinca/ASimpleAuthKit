import Foundation

public struct AuthConfig {
    let tosURL: URL?
    let privacyPolicyURL: URL?
    let keychainAccessGroup: String?
    let appleUserPersister: ((_ appleUserID: String, _ firebaseUID: String) -> Void)?

    public init(
        tosURL: URL? = nil,
        privacyPolicyURL: URL? = nil,
        keychainAccessGroup: String? = nil,
        appleUserPersister: ((String, String) -> Void)? = nil
    ) {
        self.tosURL = tosURL
        self.privacyPolicyURL = privacyPolicyURL
        self.keychainAccessGroup = keychainAccessGroup
        self.appleUserPersister = appleUserPersister
    }
}