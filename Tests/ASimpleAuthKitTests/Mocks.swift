import Foundation
import Combine
import UIKit
import XCTest
import FirebaseAuth
@testable import ASimpleAuthKit

// MARK: - MockSecureStorage
@MainActor
class MockSecureStorage: SecureStorageProtocol {
    var storage: [String: String] = [:]
    var saveUserIDCallCount = 0
    var getLastUserIDCallCount = 0
    var clearUserIDCallCount = 0
    var lastSavedUserID: String?
    var saveError: Error?
    var clearError: Error?

    let service: String
    let accessGroup: String?
    private let account = "lastUserID"

    init(service: String? = nil, accessGroup: String? = nil) {
        if let explicitService = service {
            self.service = explicitService
        } else if accessGroup != nil {
            self.service = "io.appsimple.ASimpleAuthKit.SharedAuth"
        } else {
            self.service = Bundle(for: MockSecureStorage.self).bundleIdentifier ?? "com.example.ASimpleAuthKitTests.DefaultTestBundleID"
        }
        self.accessGroup = accessGroup
    }

    func saveLastUserID(_ userID: String) async throws {
        if let error = saveError { throw error }
        saveUserIDCallCount += 1
        lastSavedUserID = userID
        storage["\(service)-\(account)"] = userID
    }

    func getLastUserID() async -> String? {
        getLastUserIDCallCount += 1
        return storage["\(service)-\(account)"]
    }

    func clearLastUserID() async throws {
        if let error = clearError { throw error }
        clearUserIDCallCount += 1
        storage.removeValue(forKey: "\(service)-\(account)")
    }

    func reset() {
        storage.removeAll()
        saveUserIDCallCount = 0; getLastUserIDCallCount = 0; clearUserIDCallCount = 0
        lastSavedUserID = nil; saveError = nil; clearError = nil
    }
}

// MARK: - MockBiometricAuthenticator
@MainActor
class MockBiometricAuthenticator: BiometricAuthenticatorProtocol {
    var mockIsAvailable = true
    var mockBiometryType = "Mock Biometrics"
    var authResultProvider: (() -> Result<Void, AuthError>)? = { .success(()) }

    var authenticateCallCount = 0
    var lastAuthReason: String?

    var isBiometricsAvailable: Bool { mockIsAvailable }
    var biometryTypeString: String { mockBiometryType }

    func authenticate(reason: String, completion: @escaping (Result<Void, AuthError>) -> Void) {
        authenticateCallCount += 1
        lastAuthReason = reason
        let result = authResultProvider?() ?? .failure(.unknown)
        DispatchQueue.main.async { completion(result) }
    }

    func reset() {
        authResultProvider = { .success(()) }; authenticateCallCount = 0; lastAuthReason = nil
        mockIsAvailable = true; mockBiometryType = "Mock Biometrics"
    }
}

// MARK: - MockFirebaseAuthenticator
@MainActor
class MockFirebaseAuthenticator: FirebaseAuthenticatorProtocol {
    var signInWithEmailResultProvider: ((String, String) -> Result<AuthUser, AuthError>)?
    var createAccountWithEmailResultProvider: ((String, String, String?) -> Result<AuthUser, AuthError>)?
    var signInWithGoogleResultProvider: ((UIViewController) -> Result<AuthUser, AuthError>)?
    var signInWithAppleResultProvider: ((UIViewController, String) -> Result<AuthUser, AuthError>)?
    var sendPasswordResetEmailError: AuthError?
    var linkCredentialResultProvider: ((AuthCredential, FirebaseAuth.User) -> Result<AuthUser, AuthError>)?
    var sendEmailVerificationError: AuthError?

    private(set) var pendingCredentialForLinking: AuthCredential?

    var signInWithEmailCallCount = 0
    var createAccountWithEmailCallCount = 0
    var signInWithGoogleCallCount = 0
    var signInWithAppleCallCount = 0
    var sendPasswordResetEmailCallCount = 0
    var sendEmailVerificationCallCount = 0
    var linkCredentialCallCount = 0
    var clearTemporaryCredentialsCallCount = 0

    init() { }

    func signInWithEmail(email: String, password: String) async throws -> AuthUser {
        signInWithEmailCallCount += 1
        guard let provider = signInWithEmailResultProvider else { XCTFail("signInWithEmailResultProvider not set."); throw AuthError.unknown }
        return try processMockResult(provider(email, password))
    }

    func createAccountWithEmail(email: String, password: String, displayName: String?) async throws -> AuthUser {
        createAccountWithEmailCallCount += 1
        guard let provider = createAccountWithEmailResultProvider else { XCTFail("createAccountWithEmailResultProvider not set."); throw AuthError.unknown }
        return try processMockResult(provider(email, password, displayName))
    }

    func signInWithGoogle(presentingViewController: UIViewController) async throws -> AuthUser {
        signInWithGoogleCallCount += 1
        guard let provider = signInWithGoogleResultProvider else { XCTFail("signInWithGoogleResultProvider not set."); throw AuthError.unknown }
        return try processMockResult(provider(presentingViewController))
    }

    func signInWithApple(presentingViewController: UIViewController, rawNonce: String) async throws -> AuthUser {
        signInWithAppleCallCount += 1
        guard let provider = signInWithAppleResultProvider else { XCTFail("signInWithAppleResultProvider not set."); throw AuthError.unknown }
        return try processMockResult(provider(presentingViewController, rawNonce))
    }
    
    func sendEmailVerification(to firebaseUser: User) async throws {
        sendEmailVerificationCallCount += 1
        if let error = sendEmailVerificationError { throw error }
    }

    func sendPasswordResetEmail(to email: String) async throws {
        sendPasswordResetEmailCallCount += 1
        if let error = sendPasswordResetEmailError { throw error }
    }

    func linkCredential(_ credentialToLink: AuthCredential, to user: FirebaseAuth.User) async throws -> AuthUser {
        linkCredentialCallCount += 1
        guard let provider = linkCredentialResultProvider else { XCTFail("linkCredentialResultProvider not set."); throw AuthError.unknown }
        return try processMockResult(provider(credentialToLink, user))
    }

    func clearTemporaryCredentials() {
        clearTemporaryCredentialsCallCount += 1
        pendingCredentialForLinking = nil
    }
    
    func forcePendingCredentialForLinking(_ cred: AuthCredential?) {
        self.pendingCredentialForLinking = cred
    }

    private func processMockResult(_ result: Result<AuthUser, AuthError>) throws -> AuthUser {
        switch result {
        case .success(let user): return user
        case .failure(let error): throw error
        }
    }

    func reset() {
        signInWithEmailResultProvider = nil; createAccountWithEmailResultProvider = nil; signInWithGoogleResultProvider = nil; signInWithAppleResultProvider = nil; sendPasswordResetEmailError = nil; linkCredentialResultProvider = nil; sendEmailVerificationError = nil
        pendingCredentialForLinking = nil
        signInWithEmailCallCount = 0; createAccountWithEmailCallCount = 0; signInWithGoogleCallCount = 0; signInWithAppleCallCount = 0; sendPasswordResetEmailCallCount = 0; linkCredentialCallCount = 0; clearTemporaryCredentialsCallCount = 0; sendEmailVerificationCallCount = 0
    }
}

// MARK: - MockFirebaseAuthClient
@MainActor
class MockFirebaseAuthClient: FirebaseAuthClientProtocol {
    var mockCurrentUser: FirebaseAuth.User?
    var mockSignOutError: Error?
    var mockSignInWithEmailResult: Result<AuthDataResult, Error>?
    var mockCreateUserResult: Result<AuthDataResult, Error>?
    var mockSendEmailVerificationError: Error?
    var mockSendPasswordResetError: Error?
    var mockSignInWithCredentialResult: Result<AuthDataResult, Error>?
    var mockLinkCredentialResult: Result<AuthDataResult, Error>?

    var signOutCallCount = 0
    var addStateDidChangeListenerCallCount = 0
    var removeStateDidChangeListenerCallCount = 0
    
    private var listeners: [Int: (FirebaseAuth.Auth, FirebaseAuth.User?) -> Void] = [:]
    private var nextListenerHandle: Int = 0

    var currentUser: FirebaseAuth.User? { mockCurrentUser }

    func addStateDidChangeListener(_ listener: @escaping (FirebaseAuth.Auth, FirebaseAuth.User?) -> Void) -> AuthStateDidChangeListenerHandle {
        addStateDidChangeListenerCallCount += 1
        let handle = nextListenerHandle
        listeners[handle] = listener
        nextListenerHandle += 1
        return handle as AuthStateDidChangeListenerHandle
    }

    func removeStateDidChangeListener(_ handle: AuthStateDidChangeListenerHandle) {
        removeStateDidChangeListenerCallCount += 1
        listeners.removeValue(forKey: handle as! Int)
    }

    func signOut() throws {
        signOutCallCount += 1
        if let error = mockSignOutError { throw error }
        mockCurrentUser = nil
        simulateAuthStateChange(to: nil)
    }
    
    func simulateAuthStateChange(to user: FirebaseAuth.User?) {
        mockCurrentUser = user
        for listener in listeners.values {
            listener(Auth.auth(), user) // Pass dummy Auth.auth() object
        }
    }

    func signIn(withEmail email: String, password: String) async throws -> AuthDataResult {
        guard let result = mockSignInWithEmailResult else { XCTFail("mockSignInWithEmailResult not set."); throw AuthError.unknown }
        return try result.get()
    }

    func createUser(withEmail email: String, password: String) async throws -> AuthDataResult {
        guard let result = mockCreateUserResult else { XCTFail("mockCreateUserResult not set."); throw AuthError.unknown }
        return try result.get()
    }
    
    func sendEmailVerification(for user: FirebaseAuth.User) async throws {
        if let error = mockSendEmailVerificationError { throw error }
    }

    func sendPasswordReset(withEmail email: String) async throws {
        if let error = mockSendPasswordResetError { throw error }
    }

    func signIn(with credential: AuthCredential) async throws -> AuthDataResult {
        guard let result = mockSignInWithCredentialResult else { XCTFail("mockSignInWithCredentialResult not set."); throw AuthError.unknown }
        return try result.get()
    }

    func link(user: FirebaseAuth.User, with credential: AuthCredential) async throws -> AuthDataResult {
        guard let result = mockLinkCredentialResult else { XCTFail("mockLinkCredentialResult not set."); throw AuthError.unknown }
        return try result.get()
    }

    func reset() {
        mockCurrentUser = nil; mockSignOutError = nil; listeners.removeAll(); nextListenerHandle = 0; signOutCallCount = 0; addStateDidChangeListenerCallCount = 0; removeStateDidChangeListenerCallCount = 0
        mockSignInWithEmailResult = nil; mockCreateUserResult = nil; mockSendEmailVerificationError = nil; mockSendPasswordResetError = nil; mockSignInWithCredentialResult = nil; mockLinkCredentialResult = nil
    }
}

// MARK: - Test Helpers
func createDummyAuthUser(uid: String = "dummyUID", email: String? = "dummy@test.com", displayName: String? = "Dummy", isAnonymous: Bool = false, providerID: String? = "password") -> AuthUser {
    return AuthUser(uid: uid, email: email, displayName: displayName, isAnonymous: isAnonymous, providerID: providerID)
}

func createDummyFirebaseUser(uid: String = "dummyUID", email: String? = "dummy@test.com", displayName: String? = "Dummy", isAnonymous: Bool = false, providerID: String? = "password") -> FirebaseAuth.User {
    return MockFirebaseUser(uid: uid, email: email, displayName: displayName, isAnonymous: isAnonymous, providerID: providerID).asFirebaseAuthUser()
}

class DummyViewController: UIViewController { }

enum TestError: Error, LocalizedError {
    case unexpectedState(String)
}

func createPlaceholderAuthCredential(providerID: String = "password") -> AuthCredential {
    switch providerID {
    case "google.com": return GoogleAuthProvider.credential(withIDToken: "dummyGoogleIDToken", accessToken: "dummyGoogleAccessToken")
    case "apple.com": return OAuthProvider.appleCredential(withIDToken: "dummyAppleIDToken", rawNonce: "dummyRawNonce", fullName: nil)
    default: return EmailAuthProvider.credential(withEmail: "test@example.com", password: "password")
    }
}

private class MockFirebaseUser: NSObject {
    // Store properties to return
    private let _uid: String
    private let _email: String?
    private let _displayName: String?
    private let _isAnonymous: Bool
    private let _providerData: [MockUserInfo]
    
    init(uid: String, email: String?, displayName: String?, isAnonymous: Bool, providerID: String?) {
        self._uid = uid
        self._email = email
        self._displayName = displayName
        self._isAnonymous = isAnonymous
        self._providerData = [MockUserInfo(providerID: providerID ?? "")]
    }

    // Use Obj-C runtime exposure to pretend to be a FirebaseAuth.User
    // This avoids subclassing/override issues and is a common mocking technique.
    override func responds(to aSelector: Selector!) -> Bool {
        // This makes our mock "claim" it can respond to any selector from User
        if super.responds(to: aSelector) { return true }
        return aSelector == #selector(getter: User.uid) ||
               aSelector == #selector(getter: User.email) ||
               aSelector == #selector(getter: User.displayName) ||
               aSelector == #selector(getter: User.isAnonymous) ||
               aSelector == #selector(getter: User.providerData)
    }

    override func forwardingTarget(for aSelector: Selector!) -> Any? {
        // This is a simplified way to redirect calls. For simple property getters,
        // we can just return our mock object itself and use @objc properties.
        return self
    }

    // Expose properties to the Objective-C runtime using @objc
    @objc var uid: String { _uid }
    @objc var email: String? { _email }
    @objc var displayName: String? { _displayName }
    @objc var isAnonymous: Bool { _isAnonymous }
    @objc var providerData: [MockUserInfo] { _providerData }
}

extension MockFirebaseUser {
    func asFirebaseAuthUser() -> User {
        return unsafeBitCast(self, to: User.self)
    }
}

private class MockUserInfo: NSObject, UserInfo {
    private let _providerID: String
    
    init(providerID: String) {
        self._providerID = providerID
    }
    
    // Expose properties to Objective-C runtime
    @objc var providerID: String { _providerID }
    @objc var uid: String { "mock-provider-uid" } // Provide a default
    @objc var displayName: String? { nil }
    @objc var email: String? { nil }
    @objc var phoneNumber: String? { nil }
    @objc var photoURL: URL? { nil }
}
