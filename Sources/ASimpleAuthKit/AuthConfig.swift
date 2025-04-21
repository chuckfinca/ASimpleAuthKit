// Sources/AuthKit/AuthConfig.swift
import Foundation
import FirebaseAuthUI // Required for FUIAuthProvider

public struct AuthConfig {
    let providers: [FUIAuthProvider] // e.g., [FUIEmailAuth(), FUIGoogleAuth(), FUIOAuth.appleAuthProvider()]
    let tosURL: URL?
    let privacyPolicyURL: URL?
    let appleUserPersister: ((_ appleUserID: String, _ firebaseUID: String) -> Void)? // Callback to persist stable Apple User ID mapping
    let appleUserRetriever: ((_ appleUserID: String) -> String?)? // Callback to retrieve Firebase UID for a given Apple User ID

    public init(
        providers: [FUIAuthProvider],
        tosURL: URL? = nil,
        privacyPolicyURL: URL? = nil,
        appleUserPersister: ((String, String) -> Void)? = nil,
        appleUserRetriever: ((String) -> String?)? = nil
    ) {
        self.providers = providers
        self.tosURL = tosURL
        self.privacyPolicyURL = privacyPolicyURL
        self.appleUserPersister = appleUserPersister
        self.appleUserRetriever = appleUserRetriever
    }
}
//next steps are to extract-files and create a claud project. ask how the package looks (separateion of concerns, best practices, secure, modern principles, easy to drop into an app, etc.), any obvious bugs. then get the tests passing, then integrate into app.
