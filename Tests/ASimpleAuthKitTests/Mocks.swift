import Foundation
import Combine
import UIKit
import XCTest // Needed for XCTFail in publisher helper
import FirebaseAuth // For AuthCredential
@testable import ASimpleAuthKit // Import your library

// --- Mock Secure Storage ---
@MainActor // Ensure accessed on main actor if AuthService expects it
class MockSecureStorage: SecureStorageProtocol {
    var storage: [String: String] = [:]
    var saveUserIDCallCount = 0
    var getLastUserIDCallCount = 0
    var clearUserIDCallCount = 0
    var lastSavedUserID: String?
    var saveError: Error?
    var clearError: Error?

    // Track service/group used
    let service: String
    let accessGroup: String?
    private let account = "lastUserID" // Keep account name constant

    // Test initializer matching the protocol needs
    init(service: String? = nil, accessGroup: String? = nil) {
        // Simulate the logic from KeychainStorage's internal init
        if let explicitService = service {
            self.service = explicitService
        } else if let group = accessGroup {
            // Use the constant for shared items defined in KeychainStorage
            self.service = "io.appsimple.ASimpleAuthKit.SharedAuth" // Match constant
        } else {
            // Use test bundle ID or a fallback - Important for isolated tests
            // Make sure this matches the expectation in the test
            // Using Bundle(for:) ensures it gets the test bundle ID when run from tests
             self.service = Bundle(for: MockSecureStorage.self).bundleIdentifier ?? "com.example.DefaultTestBundleID"
        }
        self.accessGroup = accessGroup
        print("MockSecureStorage initialized for service: '\(self.service)' \(self.accessGroup != nil ? "group: '\(self.accessGroup!)'" : "(no group)")")
    }


    func saveLastUserID(_ userID: String) throws {
        // Throw before doing anything else if error is set
        if let error = saveError {
            print("MockSecureStorage: Throwing simulated save error: \(error)")
            throw error
        }
        // Increment count *before* potential failure point (more realistic)
        saveUserIDCallCount += 1
        lastSavedUserID = userID
        let key = "\(service)-\(account)" // Use service and account for key
        storage[key] = userID // Simulate namespacing by service/account
        print("MockSecureStorage: Saved '\(userID)' for key '\(key)'")
    }

    func getLastUserID() -> String? {
        getLastUserIDCallCount += 1
        let key = "\(service)-\(account)"
        let uid = storage[key]
        print("MockSecureStorage: Retrieving for key '\(key)', found: \(uid ?? "nil")")
        return uid
    }

    func clearLastUserID() throws {
        // Throw before doing anything else if error is set
        if let error = clearError {
            print("MockSecureStorage: Throwing simulated clear error: \(error)")
            throw error
        }
        // Increment count *before* potential failure point
        clearUserIDCallCount += 1
        let key = "\(service)-\(account)"
        let oldValue = storage.removeValue(forKey: key)
        print("MockSecureStorage: Cleared for key '\(key)', removed: \(oldValue ?? "nil")")
    }

    func reset() {
        storage.removeAll()
        saveUserIDCallCount = 0
        getLastUserIDCallCount = 0
        clearUserIDCallCount = 0
        lastSavedUserID = nil
        saveError = nil
        clearError = nil
        print("MockSecureStorage: Reset.")
    }
}

// --- Mock Biometric Authenticator ---
@MainActor
class MockBiometricAuthenticator: BiometricAuthenticatorProtocol {
    var mockIsAvailable = true
    var mockBiometryType = "Mock Biometrics"
    var authResultProvider: (() -> Result<Void, AuthError>)? = { .success(()) } // Use closure for dynamic results

    var authenticateCallCount = 0
    var lastAuthReason: String?

    var isBiometricsAvailable: Bool {
        print("MockBiometricAuthenticator: isBiometricsAvailable checked, returning \(mockIsAvailable)")
        return mockIsAvailable
    }
    var biometryTypeString: String { mockBiometryType }

    func authenticate(reason: String, completion: @escaping (Result<Void, AuthError>) -> Void) {
        authenticateCallCount += 1
        lastAuthReason = reason
        print("MockBiometricAuthenticator: Authenticate called (\(authenticateCallCount)) with reason: \(reason)")
        guard let provider = authResultProvider else {
            print("MockBiometricAuthenticator: No result provider set, completing with unknown error.")
            DispatchQueue.main.async { completion(.failure(.unknown)) }
            return
        }
        let result = provider()
        print("MockBiometricAuthenticator: Provided result: \(result)")
        // Simulate async callback
        DispatchQueue.main.async {
            completion(result)
        }
    }

    func reset() {
        authResultProvider = { .success(()) }
        authenticateCallCount = 0
        lastAuthReason = nil
        mockIsAvailable = true
        mockBiometryType = "Mock Biometrics"
        print("MockBiometricAuthenticator: Reset.")
    }
}

// --- Mock Firebase Authenticator ---
@MainActor
class MockFirebaseAuthenticator: FirebaseAuthenticatorProtocol {

    // --- Configuration & Dependencies ---
    let config: AuthConfig
    let secureStorage: SecureStorageProtocol // Still useful for config, though side effects removed

    // --- Mock Control Properties ---
    /// If set, `presentSignInUI` returns this result immediately.
    var signInResultProvider: (() -> Result<AuthUser, Error>)?
    /// If `signInResultProvider` is nil, `presentSignInUI` stores the continuation here.
    var signInContinuation: CheckedContinuation<AuthUser, Error>?

    // Stored credentials are now just for inspection by tests, not cleared by mock
    var mockPendingCredentialForLinking: AuthCredential?
    var mockExistingCredentialForMergeConflict: AuthCredential?

    // --- Call Tracking ---
    var presentSignInUICallCount = 0
    var clearTemporaryCredentialsCallCount = 0
    var lastPresentingVC: UIViewController?

    // --- Protocol Conformance ---
    var pendingCredentialForLinking: AuthCredential? { mockPendingCredentialForLinking }
    var existingCredentialForMergeConflict: AuthCredential? { mockExistingCredentialForMergeConflict }

    // Helper to create the placeholder when needed
    private func createPlaceholderCredential() -> AuthCredential {
        return EmailAuthProvider.credential(
            withEmail: "test@example.com",
            password: "fakepassword"
        )
    }

    // --- Initialization ---
    init(config: AuthConfig, secureStorage: SecureStorageProtocol) {
        self.config = config
        self.secureStorage = secureStorage
    }

    // --- Protocol Methods ---
    func presentSignInUI(from viewController: UIViewController) async throws -> AuthUser {
        presentSignInUICallCount += 1
        lastPresentingVC = viewController
        print("MockFirebaseAuthenticator: presentSignInUI called (\(presentSignInUICallCount)).")

        // Option 1: Immediate result via provider
        if let provider = signInResultProvider {
            print("MockFirebaseAuthenticator: Using signInResultProvider.")
            let result = provider()
            print("MockFirebaseAuthenticator: Provided result: \(result)")

            // Simulate storing credentials *before* throwing for specific errors
            // This simulates what the actual FirebaseUI delegate method does
            if case .failure(let error) = result, let authError = error as? AuthError {
                 switch authError {
                 case .accountLinkingRequired:
                     print("MockFirebaseAuthenticator: Simulating storage of pending credential.")
                     // Set the mock credential so AuthService can retrieve it
                     self.mockPendingCredentialForLinking = createPlaceholderCredential()
                 case .mergeConflictRequired:
                     print("MockFirebaseAuthenticator: Simulating storage of existing credential.")
                      // Set the mock credential so AuthService can retrieve it
                     self.mockExistingCredentialForMergeConflict = createPlaceholderCredential()
                 default:
                     break // No credential action for other errors
                 }
             }

            // Now return result or throw error
            switch result {
            case .success(let user):
                return user
            case .failure(let error):
                 // NOTE: We no longer call simulateCredentialClearingOnError here.
                 // The mock's job is just to return the error. AuthService decides whether to clear.
                throw error
            }
        }
        // Option 2: Hang using continuation
            else {
            print("MockFirebaseAuthenticator: No result provider, using continuation.")
            // Cancel any previous hanging continuation before storing a new one
            if let existingContinuation = signInContinuation {
                print("MockFirebaseAuthenticator: Warning - Overwriting existing continuation.")
                existingContinuation.resume(throwing: AuthError.cancelled) // Cancel previous one
            }
            return try await withCheckedThrowingContinuation { continuation in
                self.signInContinuation = continuation // Store the new continuation
            }
        }
    }

    /// Helper to complete a previously stored continuation.
    func completeSignIn(result: Result<AuthUser, Error>) {
        guard let continuation = signInContinuation else {
            print("MockFirebaseAuthenticator: No continuation to complete.")
            return
        }
        print("MockFirebaseAuthenticator: Completing continuation with result: \(result)")
        self.signInContinuation = nil // Clear before resuming

        // Perform side effects *before* resuming (like setting credentials)
        Task { @MainActor in
            if case .failure(let error) = result, let authError = error as? AuthError {
                 switch authError {
                 case .accountLinkingRequired:
                     print("MockFirebaseAuthenticator: Simulating storage of pending credential (continuation).")
                     self.mockPendingCredentialForLinking = createPlaceholderCredential()
                 case .mergeConflictRequired:
                     print("MockFirebaseAuthenticator: Simulating storage of existing credential (continuation).")
                     self.mockExistingCredentialForMergeConflict = createPlaceholderCredential()
                 default:
                     break
                 }
             }

            // Resume the continuation
            switch result {
            case .success(let user):
                continuation.resume(returning: user)
            case .failure(let error):
                // NOTE: No call to simulateCredentialClearingOnError here either.
                continuation.resume(throwing: error)
            }
        }
    }

    // <<< REVISED >>>
    func clearTemporaryCredentials() {
        // This method ONLY tracks the call count.
        // It does NOT modify the mock's credential properties.
        clearTemporaryCredentialsCallCount += 1
        print("MockFirebaseAuthenticator: clearTemporaryCredentials called (\(clearTemporaryCredentialsCallCount)). Mock credentials remain for inspection.")
        // Intentionally removed:
        // mockPendingCredentialForLinking = nil
        // mockExistingCredentialForMergeConflict = nil
    }

    /// Resets mock state, including cancelling any hanging continuation.
    func reset() {
        signInResultProvider = nil
        if let cont = signInContinuation {
            print("MockFirebaseAuthenticator: Resetting - Cancelling hanging continuation.")
            cont.resume(throwing: AuthError.cancelled) // Ensure hanging tasks can complete
            signInContinuation = nil
        }
        // Clear credentials only on explicit reset
        mockPendingCredentialForLinking = nil
        mockExistingCredentialForMergeConflict = nil
        presentSignInUICallCount = 0
        clearTemporaryCredentialsCallCount = 0
        lastPresentingVC = nil
        print("MockFirebaseAuthenticator: Reset.")
    }

    // --- Private Helpers ---
    // <<< REMOVED simulateCredentialClearingOnError >>>
    // This logic is now handled by AuthService itself.
}

// MARK: - Test Helpers

// Helper to create a dummy user using the internal initializer
func createDummyUser(uid: String = "dummyUID", email: String? = "dummy@test.com", displayName: String? = "Dummy", isAnonymous: Bool = false, providerID: String? = "password") -> AuthUser {
    return AuthUser(uid: uid, email: email, displayName: displayName, isAnonymous: isAnonymous, providerID: providerID)
}

// Dummy VC for presenting calls
class DummyViewController: UIViewController { }

// Define TestError used in tests
enum TestError: Error, LocalizedError {
    case unexpectedState(String)
    case timeout(String) // Add description to timeout
    case testSetupFailed(String) // More specific setup error

    var errorDescription: String? {
        switch self {
        case .unexpectedState(let msg): return "TestError: Unexpected State - \(msg)"
        case .timeout(let msg): return "TestError: Asynchronous operation timed out waiting for: \(msg)."
        case .testSetupFailed(let msg): return "TestError: Test setup failed - \(msg)"
        }
    }
}
