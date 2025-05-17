import Foundation
import Combine
import UIKit
import XCTest
import FirebaseAuth
@testable import ASimpleAuthKit // For internal types like AuthUser internal init

// MARK: - MockSecureStorage (Largely Unchanged, ensure it's up-to-date from previous context)
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

// MARK: - MockBiometricAuthenticator (Largely Unchanged, ensure it's up-to-date)
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

// MARK: - MockFirebaseAuthenticator (Significant Updates)
@MainActor
class MockFirebaseAuthenticator: FirebaseAuthenticatorProtocol {

    // --- Configuration & Dependencies (if needed by mock logic) ---
    // let config: AuthConfig // Not strictly needed by mock if not using its properties
    // let secureStorage: SecureStorageProtocol // Not strictly needed by mock

    // --- Mock Control Properties for each method ---
    var signInWithEmailResultProvider: ((String, String) -> Result<AuthUser, AuthError>)?
    var createAccountWithEmailResultProvider: ((String, String, String?) -> Result<AuthUser, AuthError>)?
    var signInWithGoogleResultProvider: ((UIViewController) -> Result<AuthUser, AuthError>)?
    var signInWithAppleResultProvider: ((UIViewController, String) -> Result<AuthUser, AuthError>)?
    var sendPasswordResetEmailError: AuthError?
    var linkCredentialResultProvider: ((AuthCredential, FirebaseAuth.User) -> Result<AuthUser, AuthError>)?

    // --- Stored credentials for inspection / linking flow simulation ---
    private(set) var pendingCredentialForLinking: AuthCredential?
    // existingCredentialForMergeConflict may not be needed explicitly if merge is part of linking failure
    // private(set) var existingCredentialForMergeConflict: AuthCredential?


    // --- Call Tracking ---
    var signInWithEmailCallCount = 0
    var createAccountWithEmailCallCount = 0
    var signInWithGoogleCallCount = 0
    var signInWithAppleCallCount = 0
    var sendPasswordResetEmailCallCount = 0
    var linkCredentialCallCount = 0
    var clearTemporaryCredentialsCallCount = 0

    var lastEmailForSignIn: String?
    var lastPasswordForSignIn: String?
    var lastDisplayNameForCreate: String?
    var lastPresentingVCForGoogle: UIViewController?
    var lastPresentingVCForApple: UIViewController?
    var lastRawNonceForApple: String?
    var lastEmailForPasswordReset: String?
    var lastCredentialLinked: AuthCredential?
    var lastUserForLinking: FirebaseAuth.User?


    // --- Initialization ---
    // init(config: AuthConfig, secureStorage: SecureStorageProtocol) {
    //     self.config = config
    //     self.secureStorage = secureStorage
    // }
    // Simplified init if config/storage not directly used by mock logic
    init() {}


    // --- Protocol Methods Implementation ---

    func signInWithEmail(email: String, password: String) async throws -> AuthUser {
        signInWithEmailCallCount += 1
        lastEmailForSignIn = email
        lastPasswordForSignIn = password
        print("MockFirebaseAuthenticator: signInWithEmail called for \(email).")
        guard let provider = signInWithEmailResultProvider else {
            XCTFail("MockFirebaseAuthenticator: signInWithEmailResultProvider not set.")
            throw AuthError.unknown // Should not happen in a well-written test
        }
        let result = provider(email, password)
        return try processMockResult(result)
    }

    func createAccountWithEmail(email: String, password: String, displayName: String?) async throws -> AuthUser {
        createAccountWithEmailCallCount += 1
        lastEmailForSignIn = email // Re-use for simplicity
        lastPasswordForSignIn = password
        lastDisplayNameForCreate = displayName
        print("MockFirebaseAuthenticator: createAccountWithEmail called for \(email).")
        guard let provider = createAccountWithEmailResultProvider else {
            XCTFail("MockFirebaseAuthenticator: createAccountWithEmailResultProvider not set.")
            throw AuthError.unknown
        }
        let result = provider(email, password, displayName)
        return try processMockResult(result)
    }

    func signInWithGoogle(presentingViewController: UIViewController) async throws -> AuthUser {
        signInWithGoogleCallCount += 1
        lastPresentingVCForGoogle = presentingViewController
        print("MockFirebaseAuthenticator: signInWithGoogle called.")
        guard let provider = signInWithGoogleResultProvider else {
            XCTFail("MockFirebaseAuthenticator: signInWithGoogleResultProvider not set.")
            throw AuthError.unknown
        }
        let result = provider(presentingViewController)
        return try processMockResult(result)
    }

    func signInWithApple(presentingViewController: UIViewController, rawNonce: String) async throws -> AuthUser {
        signInWithAppleCallCount += 1
        lastPresentingVCForApple = presentingViewController
        lastRawNonceForApple = rawNonce
        print("MockFirebaseAuthenticator: signInWithApple called with nonce.")
        guard let provider = signInWithAppleResultProvider else {
            XCTFail("MockFirebaseAuthenticator: signInWithAppleResultProvider not set.")
            throw AuthError.unknown
        }
        let result = provider(presentingViewController, rawNonce)
        return try processMockResult(result)
    }

    func sendPasswordResetEmail(to email: String) async throws {
        sendPasswordResetEmailCallCount += 1
        lastEmailForPasswordReset = email
        print("MockFirebaseAuthenticator: sendPasswordResetEmail called for \(email).")
        if let error = sendPasswordResetEmailError {
            throw error
        }
        // No return value for success
    }

    func linkCredential(_ credentialToLink: AuthCredential, to user: FirebaseAuth.User) async throws -> AuthUser {
        linkCredentialCallCount += 1
        lastCredentialLinked = credentialToLink
        lastUserForLinking = user
        print("MockFirebaseAuthenticator: linkCredential called for user \(user.uid) with provider \(credentialToLink.provider).")
        guard let provider = linkCredentialResultProvider else {
            XCTFail("MockFirebaseAuthenticator: linkCredentialResultProvider not set.")
            throw AuthError.unknown
        }
        let result = provider(credentialToLink, user)
        return try processMockResult(result, isLinking: true) // Pass isLinking context
    }
    
    private func processMockResult(_ result: Result<AuthUser, AuthError>, isLinking: Bool = false) throws -> AuthUser {
        switch result {
        case .success(let user):
            // If this success is for an initial sign-in (not linking re-auth),
            // and there was a pending credential, it implies the re-auth was for linking.
            // However, the mock's job is simpler: just return the user.
            // AuthService handles the logic of "was there a pending credential?"
            print("MockFirebaseAuthenticator: Result is success for user \(user.uid)")
            if !isLinking { // Only clear if it's not part of the linkCredential call itself
                self.pendingCredentialForLinking = nil // Successful sign-in clears any prior pending state
            }
            return user
        case .failure(let error):
            print("MockFirebaseAuthenticator: Result is failure: \(error.localizedDescription)")
            // Simulate FirebaseAuthenticator's behavior of populating pendingCredentialForLinking
            // if the error indicates account linking is required.
            if case .accountLinkingRequired(_, let cred) = error {
                print("MockFirebaseAuthenticator: Simulating storage of pending credential due to .accountLinkingRequired error.")
                self.pendingCredentialForLinking = cred
            } else if !isLinking { // Don't clear if the linkCredential call itself failed
                self.pendingCredentialForLinking = nil // Other errors clear it
            }
            throw error
        }
    }

    func clearTemporaryCredentials() {
        clearTemporaryCredentialsCallCount += 1
        pendingCredentialForLinking = nil
        // existingCredentialForMergeConflict = nil
        print("MockFirebaseAuthenticator: clearTemporaryCredentials called. Mock's pending cred cleared.")
    }

    // --- Mock Reset and Helper ---
    func reset() {
        signInWithEmailResultProvider = nil
        createAccountWithEmailResultProvider = nil
        signInWithGoogleResultProvider = nil
        signInWithAppleResultProvider = nil
        sendPasswordResetEmailError = nil
        linkCredentialResultProvider = nil

        pendingCredentialForLinking = nil
        // existingCredentialForMergeConflict = nil

        signInWithEmailCallCount = 0
        createAccountWithEmailCallCount = 0
        signInWithGoogleCallCount = 0
        signInWithAppleCallCount = 0
        sendPasswordResetEmailCallCount = 0
        linkCredentialCallCount = 0
        clearTemporaryCredentialsCallCount = 0

        lastEmailForSignIn = nil; lastPasswordForSignIn = nil; lastDisplayNameForCreate = nil
        lastPresentingVCForGoogle = nil; lastPresentingVCForApple = nil; lastRawNonceForApple = nil
        lastEmailForPasswordReset = nil; lastCredentialLinked = nil; lastUserForLinking = nil
        print("MockFirebaseAuthenticator: Reset.")
    }
}


// MARK: - Test Helpers (createDummyUser, DummyViewController, TestError)
// (Ensure these are present and up-to-date from previous context if not included here)
// Helper to create a dummy user using the internal initializer
func createDummyUser(uid: String = "dummyUID", email: String? = "dummy@test.com", displayName: String? = "Dummy", isAnonymous: Bool = false, providerID: String? = "password") -> AuthUser {
    return AuthUser(uid: uid, email: email, displayName: displayName, isAnonymous: isAnonymous, providerID: providerID)
}

// Dummy VC for presenting calls
class DummyViewController: UIViewController { }

// Define TestError used in tests
enum TestError: Error, LocalizedError {
    case unexpectedState(String)
    case timeout(String)
    case testSetupFailed(String)

    var errorDescription: String? {
        switch self {
        case .unexpectedState(let msg): return "TestError: Unexpected State - \(msg)"
        case .timeout(let msg): return "TestError: Asynchronous operation timed out waiting for: \(msg)."
        case .testSetupFailed(let msg): return "TestError: Test setup failed - \(msg)"
        }
    }
}

// Helper to create a placeholder AuthCredential for testing
func createPlaceholderAuthCredential(providerID: String = "password") -> AuthCredential {
    switch providerID {
    case "google.com":
        return GoogleAuthProvider.credential(withIDToken: "dummyGoogleIDToken", accessToken: "dummyGoogleAccessToken")
    case "apple.com":
        return OAuthProvider.appleCredential(withIDToken: "dummyAppleIDToken", rawNonce: "dummyRawNonce", fullName: nil)
    default: // password
        return EmailAuthProvider.credential(withEmail: "test@example.com", password: "password")
    }
}
