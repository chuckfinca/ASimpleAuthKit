// Tests/ASimpleAuthKitTests/Mocks.swift

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
    var lastClearedService: String? // Variable name seems off? Should relate to cleared item? Let's ignore for now.
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
        clearUserIDCallCount += 1
        // lastClearedService = service // This variable might be misnamed or unnecessary. Let's ignore.
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
        // lastClearedService = nil // Reset this too if kept
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

    var isBiometricsAvailable: Bool { mockIsAvailable }
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
        // Simulate async callback
        DispatchQueue.main.async {
             completion(provider())
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
    let secureStorage: SecureStorageProtocol // Needed to simulate side effects

    // --- Mock Control Properties ---
    /// If set, `presentSignInUI` returns this result immediately.
    var signInResultProvider: (() -> Result<AuthUser, Error>)?
    /// If `signInResultProvider` is nil, `presentSignInUI` stores the continuation here.
    var signInContinuation: CheckedContinuation<AuthUser, Error>?

    var mockPendingCredentialForLinking: AuthCredential?
    var mockExistingCredentialForMergeConflict: AuthCredential?

    // --- Call Tracking ---
    var presentSignInUICallCount = 0
    var clearTemporaryCredentialsCallCount = 0
    var lastPresentingVC: UIViewController?

    // --- Protocol Conformance ---
    var pendingCredentialForLinking: AuthCredential? { mockPendingCredentialForLinking }
    var existingCredentialForMergeConflict: AuthCredential? { mockExistingCredentialForMergeConflict }

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
             switch result {
             case .success(let user):
                  // Simulate storage side-effect (ignore errors in mock)
                  if !user.isAnonymous { try? await MainActor.run { try secureStorage.saveLastUserID(user.uid) } }
                  return user
             case .failure(let error):
                  // Simulate credential clearing side-effect
                  simulateCredentialClearingOnError(error)
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
            // Consider XCTFail if called unexpectedly? Or just log.
            return
        }
        print("MockFirebaseAuthenticator: Completing continuation with result: \(result)")
        self.signInContinuation = nil // Clear before resuming

        // Perform side effects *before* resuming
        Task { @MainActor in // Ensure storage access is on main actor
            switch result {
            case .success(let user):
                if !user.isAnonymous { try? secureStorage.saveLastUserID(user.uid) }
                continuation.resume(returning: user)
            case .failure(let error):
                simulateCredentialClearingOnError(error)
                continuation.resume(throwing: error)
            }
        }
    }

    func clearTemporaryCredentials() {
        clearTemporaryCredentialsCallCount += 1
        mockPendingCredentialForLinking = nil
        mockExistingCredentialForMergeConflict = nil
        print("MockFirebaseAuthenticator: clearTemporaryCredentials called (\(clearTemporaryCredentialsCallCount)).")
    }

    /// Resets mock state, including cancelling any hanging continuation.
    func reset() {
        signInResultProvider = nil
        if let cont = signInContinuation {
            print("MockFirebaseAuthenticator: Resetting - Cancelling hanging continuation.")
            cont.resume(throwing: AuthError.cancelled) // Ensure hanging tasks can complete
            signInContinuation = nil
        }
        mockPendingCredentialForLinking = nil
        mockExistingCredentialForMergeConflict = nil
        presentSignInUICallCount = 0
        clearTemporaryCredentialsCallCount = 0
        lastPresentingVC = nil
        print("MockFirebaseAuthenticator: Reset.")
    }

    // --- Private Helpers ---
    /// Encapsulates the logic for when credentials should be cleared based on error type.
    private func simulateCredentialClearingOnError(_ error: Error) {
        if let authError = error as? AuthError {
            switch authError {
            case .cancelled, .firebaseUIError, .firebaseAuthError, .missingLinkingInfo, .unknown, .configurationError, .keychainError, .accountLinkingError, .mergeConflictError:
                print("MockFirebaseAuthenticator: Simulating credential clear for error: \(authError)")
                clearTemporaryCredentials()
            case .accountLinkingRequired, .mergeConflictRequired, .biometricsFailed, .biometricsNotAvailable:
                print("MockFirebaseAuthenticator: Not clearing credentials for specific error: \(authError)")
                break // Don't clear for these specific cases
            }
        } else {
            // Clear for generic errors too
            print("MockFirebaseAuthenticator: Simulating credential clear for generic error: \(error)")
            clearTemporaryCredentials()
        }
    }
}

// MARK: - Test Helpers

// Helper to create a dummy user using the internal initializer
func createDummyUser(uid: String = "dummyUID", email: String? = "dummy@test.com", displayName: String? = "Dummy", isAnonymous: Bool = false, providerID: String? = "password") -> AuthUser {
    return AuthUser(uid: uid, email: email, displayName: displayName, isAnonymous: isAnonymous, providerID: providerID)
}

// Dummy VC for presenting calls
class DummyViewController: UIViewController {}

// Define TestError used in tests
enum TestError: Error, LocalizedError {
    case unexpectedState(String)
    case timeout
    case testSetupFailed(String) // More specific setup error

    var errorDescription: String? {
        switch self {
        case .unexpectedState(let msg): return "TestError: Unexpected State - \(msg)"
        case .timeout: return "TestError: Asynchronous operation timed out."
        case .testSetupFailed(let msg): return "TestError: Test setup failed - \(msg)"
        }
    }
}
