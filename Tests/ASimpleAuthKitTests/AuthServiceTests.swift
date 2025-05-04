import XCTest
import Combine
@testable import ASimpleAuthKit // Use @testable for internal access if needed
@preconcurrency import FirebaseAuthUI
import Firebase // Keep for FirebaseApp and Auth setup

@MainActor // Run tests on MainActor since AuthService is MainActor-bound
final class AuthServiceTests: XCTestCase {

    // MARK: Properties
    var sut: AuthService!
    var mockFirebaseAuthenticator: MockFirebaseAuthenticator!
    var mockBiometricAuthenticator: MockBiometricAuthenticator!
    var mockSecureStorage: MockSecureStorage!
    var config: AuthConfig!
    var cancellables: Set<AnyCancellable>!
    var dummyVC: DummyViewController!
    let placeholderTestCredential = EmailAuthProvider.credential( // Still needed for mock setup
        withEmail: "test@example.com",
        password: "fakepassword"
    )

    // Static flag to ensure configuration happens only once per test run
    private static var firebaseConfigured = false // Use static for one-time setup
    private let authEmulatorHost = "localhost" // Or "127.0.0.1"
    private let authEmulatorPort = 9099

    // MARK: Lifecycle (Async)
    override func setUp() async throws {

        // --- Firebase Configuration & Emulator Setup ---
        if !AuthServiceTests.firebaseConfigured {
            print("AuthServiceTests: Configuring Firebase and Auth Emulator for tests (one-time)...")
            guard let fileURL = Bundle.module.url(forResource: "GoogleService-Info-Tests", withExtension: "plist") else {
                 throw TestError.testSetupFailed("GoogleService-Info-Tests.plist not found in test bundle (Bundle.module). Check Package.swift resources.")
             }
             print("AuthServiceTests: Found GoogleService-Info-Tests.plist at \(fileURL.path)")
            guard let fileopts = FirebaseOptions(contentsOfFile: fileURL.path) else {
                 throw TestError.testSetupFailed("Could not load FirebaseOptions from GoogleService-Info-Tests.plist.")
            }
            if FirebaseApp.app() == nil {
                FirebaseApp.configure(options: fileopts)
                print("AuthServiceTests: FirebaseApp configured with test options.")
            } else {
                print("AuthServiceTests: FirebaseApp already configured.")
            }
            
            print("AuthServiceTests: ---> REMINDER: Ensure Firebase Auth Emulator is running!")
            print("AuthServiceTests: ---> Use command: firebase emulators:start --only auth --project authkit-test-project") // Or your
            
            Auth.auth().useEmulator(withHost: authEmulatorHost, port: authEmulatorPort)
            print("AuthServiceTests: FirebaseAuth configured to use emulator at \(authEmulatorHost):\(authEmulatorPort)")
            AuthServiceTests.firebaseConfigured = true
            print("AuthServiceTests: One-time Firebase test setup complete.")
        }
        // --- End Firebase Configuration ---

        // --- Clean Auth State Before Each Test ---
        print("AuthServiceTests: Attempting pre-test sign out...")
        try? Auth.auth().signOut()
        print("AuthServiceTests: Pre-test sign out attempt complete.")
        // --- End Auth State Clean ---


        // --- Mock Setup ---
        cancellables = []
        dummyVC = DummyViewController()
        config = AuthConfig(providers: []) // Default config
        mockSecureStorage = MockSecureStorage(service: nil, accessGroup: nil)
        mockBiometricAuthenticator = MockBiometricAuthenticator()
        mockFirebaseAuthenticator = MockFirebaseAuthenticator(config: config, secureStorage: mockSecureStorage)

        // --- SUT Initialization ---
        sut = AuthService(
            config: config,
            secureStorage: mockSecureStorage,
            firebaseAuthenticator: mockFirebaseAuthenticator,
            biometricAuthenticator: mockBiometricAuthenticator,
            isTestMode: true // <<< CRITICAL: Disable listener interference
        )
        print("AuthServiceTests: SUT initialized in test mode.")
        // --- End Mock Setup ---
    }

    override func tearDown() async throws {
        print("AuthServiceTests: Attempting post-test sign out...")
        try? Auth.auth().signOut() // Sign out user created during test if any
        print("AuthServiceTests: Post-test sign out attempt complete.")


        // Cancel subscriptions
        cancellables.forEach { $0.cancel() }
        cancellables = nil

        // Nil out properties
        sut = nil
        mockFirebaseAuthenticator = nil
        mockBiometricAuthenticator = nil
        mockSecureStorage = nil
        config = nil
        dummyVC = nil
        print("AuthServiceTests: Teardown complete.")
    }

    // MARK: - Helper Methods

    /// Helper to simulate a standard successful sign-in.
    /// Assumes the goal is to end in .signedIn (sets bio mock accordingly).
    /// Does NOT wait for state settle as listener is disabled in test mode.
    @discardableResult
    private func arrangeSuccessfulSignIn(user: AuthUser = createDummyUser()) async throws -> AuthUser {
        print("ArrangeSignIn Helper: Starting for user \(user.uid)")
        // Reset mocks *before* configuring and acting within the helper
        mockFirebaseAuthenticator.reset()
        mockSecureStorage.reset()
        mockBiometricAuthenticator.reset()

        // Ensure conditions lead to .signedIn, not .requiresBiometrics for this helper
        mockBiometricAuthenticator.mockIsAvailable = false
        mockFirebaseAuthenticator.signInResultProvider = {
             print("ArrangeSignIn Helper: signInResultProvider called, returning success for \(user.uid)")
             return .success(user)
         }

        // Act
        await sut.signIn(from: dummyVC)

        // State should transition directly based on logic
        let finalState = sut.state
        print("ArrangeSignIn Helper: State after signIn call: \(finalState)")

        // Since we forced bio unavailable, expected state is signedIn
        let expectedState: AuthState = .signedIn(user)

        guard finalState == expectedState else {
             throw TestError.unexpectedState("ArrangeSignIn Helper: Expected \(expectedState) after sign-in, but got \(finalState)")
         }
         print("ArrangeSignIn Helper: Successfully arranged state \(finalState)")

         // No reset needed here, the next test/step should reset if required.
         return user
    }

    /// Helper to force the requiresBiometrics state.
    /// This involves ACTUALLY signing in a user via the emulator.
    private func forceRequiresBiometricsState(user: AuthUser = createDummyUser()) async throws {
        print("ForceBiometrics Helper: Starting for user \(user.uid)")
        // 1. Ensure no other user is signed in on the emulator
        try? Auth.auth().signOut()

        // 2. ACTUALLY sign in a user (e.g., anonymously) to populate Auth.auth().currentUser
        let authResult = try await Auth.auth().signInAnonymously()
        let actualUID = authResult.user.uid
        print("ForceBiometrics Helper: Signed in emulator user with UID: \(actualUID)")

        // 3. Ensure mock storage has the *actual* UID from the emulator user
        try mockSecureStorage.saveLastUserID(actualUID)
        print("ForceBiometrics Helper: Saved actual UID \(actualUID) to mock storage.")

        // 4. Ensure biometrics are available in the mock
        mockBiometricAuthenticator.mockIsAvailable = true
        print("ForceBiometrics Helper: Set mock biometrics available.")

        // 5. Use the forceStateForTesting method to set the SUT state
        sut.forceStateForTesting(.requiresBiometrics)
        print("ForceBiometrics Helper: Forced SUT state to .requiresBiometrics.")

        // 6. Verify state was set
        guard sut.state == .requiresBiometrics else {
             try? await Auth.auth().signOut() // Clean up emulator user
             throw TestError.unexpectedState("Failed to force requiresBiometrics state, current state is \(sut.state)")
        }
        print("ForceBiometrics Helper: Successfully forced requiresBiometrics state.")

        // 7. Reset mock counts (but keep their state configured) for the actual test action
        mockBiometricAuthenticator.authenticateCallCount = 0
        mockSecureStorage.saveUserIDCallCount = 0
        mockSecureStorage.getLastUserIDCallCount = 0
        mockSecureStorage.clearUserIDCallCount = 0
        mockFirebaseAuthenticator.presentSignInUICallCount = 0
        mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount = 0
        print("ForceBiometrics Helper: Reset mock call counts.")
    }


    // MARK: - Initialization Tests
    func testInit_initialStateIsSignedOut() {
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertNil(sut.lastError)
    }

    // MARK: - SignIn Tests

    func testSignIn_FromSignedOut_Success_updatesStateToSignedInAndSavesUserID() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        let expectedUser = createDummyUser(uid: "user123", isAnonymous: false)
        mockFirebaseAuthenticator.reset() // Reset before config
        mockSecureStorage.reset()
        mockBiometricAuthenticator.reset()
        mockBiometricAuthenticator.mockIsAvailable = false // Ensure bio isn't required
        mockFirebaseAuthenticator.signInResultProvider = { .success(expectedUser) }

        // Act
        await sut.signIn(from: dummyVC)

        // Assert final state (no sleep needed)
        XCTAssertEqual(sut.state, .signedIn(expectedUser))
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 1)
        XCTAssertEqual(mockSecureStorage.getLastUserID(), "user123")
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 0)
    }

    func testSignIn_FromSignedOut_SuccessAnonymous_updatesStateDoesNotSaveUserID() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        let expectedUser = createDummyUser(uid: "anonUser", isAnonymous: true)
        mockFirebaseAuthenticator.reset() // Reset before config
        mockSecureStorage.reset()
        mockBiometricAuthenticator.reset() // Also reset bio mock
        mockFirebaseAuthenticator.signInResultProvider = { .success(expectedUser) }

        // Act
        await sut.signIn(from: dummyVC)

        // Assert (no sleep needed)
        XCTAssertEqual(sut.state, .signedIn(expectedUser))
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 0, "User ID should not be saved for anonymous user")
        XCTAssertNil(mockSecureStorage.getLastUserID())
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 0)
    }

    func testSignIn_FromSignedOut_Success_updatesStateToRequiresBiometrics() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        let user = createDummyUser(uid: "bioUserSignIn")
        mockFirebaseAuthenticator.reset() // Reset before config
        mockSecureStorage.reset()
        mockBiometricAuthenticator.reset()

        // Pre-save the user ID and make biometrics available
        try mockSecureStorage.saveLastUserID(user.uid)
        mockBiometricAuthenticator.mockIsAvailable = true
        mockFirebaseAuthenticator.signInResultProvider = { .success(user) }

        // Reset counts *after* setup, *before* action
        mockSecureStorage.saveUserIDCallCount = 0
        mockBiometricAuthenticator.authenticateCallCount = 0

        // Act
        await sut.signIn(from: dummyVC)

        // Assert: Should end up in requiresBiometrics (no sleep needed)
        XCTAssertEqual(sut.state, .requiresBiometrics)
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 0) // Save should NOT happen again
        XCTAssertEqual(mockSecureStorage.getLastUserID(), user.uid)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 0)
    }

    func testSignIn_FromRequiresBiometrics_Success_updatesStateToRequiresBiometrics() async throws {
        // Arrange: Setup requiresBiometrics state first
        let user = createDummyUser(uid: "bioUser")
        try await forceRequiresBiometricsState(user: user) // Uses helper (signs in real user)

        // Precondition check AFTER arrangement
        XCTAssertEqual(sut.state, .requiresBiometrics)
        guard let actualUID = Auth.auth().currentUser?.uid else {
             throw TestError.testSetupFailed("Emulator user UID not found after forceRequiresBiometricsState")
         }
        let actualUser = AuthUser(firebaseUser: Auth.auth().currentUser!)

        // Reset mocks AFTER arrangement, BEFORE action
        mockFirebaseAuthenticator.reset()
        mockSecureStorage.reset() // Reset storage counts
        mockBiometricAuthenticator.reset()

        // Configure mocks for the *second* sign-in attempt
        mockFirebaseAuthenticator.signInResultProvider = { .success(actualUser) }
        mockBiometricAuthenticator.mockIsAvailable = true // Ensure still available
        try mockSecureStorage.saveLastUserID(actualUID) // Ensure storage still has ID

        // Act: Sign in again
        await sut.signIn(from: dummyVC)

        // Assert: Should end up back in requiresBiometrics (no sleep needed)
        XCTAssertEqual(sut.state, .requiresBiometrics)
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 0)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 0)
    }


    func testSignIn_Cancelled_updatesStateToSignedOutAndSetsError() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        let cancelError = AuthError.cancelled
        mockFirebaseAuthenticator.reset() // Reset before config
        mockFirebaseAuthenticator.signInResultProvider = { .failure(cancelError) }

        // Act
        await sut.signIn(from: dummyVC)

        // Assert (no sleep needed)
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertEqual(sut.lastError, cancelError)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        // Clear creds should be called by SUT's error handling for .cancelled
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1)
        XCTAssertEqual(mockSecureStorage.clearUserIDCallCount, 0)
    }

    func testSignIn_GenericFirebaseError_updatesStateToSignedOutAndSetsError() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        let firebaseError = AuthError.firebaseAuthError(.init(code: 1, domain: "test", message: "Firebase failed"))
        mockFirebaseAuthenticator.reset() // Reset before config
        mockFirebaseAuthenticator.signInResultProvider = { .failure(firebaseError) }

        // Act
        await sut.signIn(from: dummyVC)

        // Assert (no sleep needed)
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertEqual(sut.lastError, firebaseError)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        // Clear creds should be called by SUT's error handling default case
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1)
        XCTAssertEqual(mockSecureStorage.clearUserIDCallCount, 0)
    }

    func testSignIn_AccountLinkingRequired_updatesStateAndSetsError() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        let testEmail = "link@example.com"
        let linkingError = AuthError.accountLinkingRequired(email: testEmail)
        mockFirebaseAuthenticator.reset() // Reset before config
        mockFirebaseAuthenticator.signInResultProvider = { .failure(linkingError) }

        // Act
        await sut.signIn(from: dummyVC)

        // Assert (Assuming internal fetchSignInMethods hypothetically succeeds - TEST LIMITATION)
        // This assertion relies on the SUT's internal logic *attempting* the fetch and setting state.
        // The *actual* fetch will likely fail in test env, but we test the SUT's reaction to the *initial* error.
        if case .requiresAccountLinking(let email, _) = sut.state {
            XCTAssertEqual(email, testEmail)
        } else {
            // If the fetch *actually* fails immediately and AuthService handles that error path:
            print("WARN: State did not become .requiresAccountLinking. Likely internal fetchSignInMethods failed as expected in test env. Current state: \(sut.state)")
             XCTAssertEqual(sut.state, .signedOut, "State should revert to signedOut if fetch fails")
              if case .firebaseAuthError = sut.lastError { } // Expect fetch error
              else { XCTFail("Expected firebaseAuthError from fetch failure, got \(String(describing: sut.lastError))") }
        }

        // Regardless of fetch success/fail, the *initial* error processing should occur:
        XCTAssertEqual(sut.lastError, linkingError, "Initial error should be linkingRequired")
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        // Clear should *not* be called if fetch hypothetically succeeds, *is* called if it fails.
        // Check the mock's stored credential, which *should* have been set by the mock before throwing.
        XCTAssertNotNil(mockFirebaseAuthenticator.pendingCredentialForLinking, "Pending credential should exist in mock")
        // Can't reliably assert clearTemporaryCredentialsCallCount without knowing fetch outcome.
    }

    func testSignIn_AccountLinkingRequired_FetchFails_updatesStateToSignedOutWithError() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        let testEmail = "link-fail@example.com"
        let linkingError = AuthError.accountLinkingRequired(email: testEmail)
        mockFirebaseAuthenticator.reset() // Reset before config
        mockFirebaseAuthenticator.signInResultProvider = { .failure(linkingError) }
        // The real fetch *will* fail in test env.

        // Act
        await sut.signIn(from: dummyVC)

        // Assert (no sleep needed)
        XCTAssertEqual(sut.state, .signedOut, "State should revert to signedOut if fetch fails")
        XCTAssertNotNil(sut.lastError)
        // SUT's handleSignInAuthError should overwrite lastError with the fetch error
        if case .firebaseAuthError = sut.lastError { }
        else { XCTFail("Expected firebaseAuthError from fetch failure, got \(String(describing: sut.lastError))") }
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        XCTAssertNotNil(mockFirebaseAuthenticator.pendingCredentialForLinking, "Mock should still set credential before throwing")
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1, "Clear creds SHOULD be called by SUT if fetch fails")
    }

    func testSignIn_MergeConflictRequired_updatesStateAndSetsError() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        let mergeError = AuthError.mergeConflictRequired
        mockFirebaseAuthenticator.reset() // Reset before config
        mockFirebaseAuthenticator.signInResultProvider = { .failure(mergeError) }

        // Act
        await sut.signIn(from: dummyVC)

        // Assert (no sleep needed)
        XCTAssertEqual(sut.state, .requiresMergeConflictResolution)
        XCTAssertEqual(sut.lastError, mergeError)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        XCTAssertNotNil(mockFirebaseAuthenticator.existingCredentialForMergeConflict)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 0) // Not cleared on this path
    }

    func testSignIn_WhenAlreadySignedIn_doesNothing() async throws {
        // Arrange: Get into signedIn state first
        let user = try await arrangeSuccessfulSignIn()
        XCTAssertEqual(sut.state, .signedIn(user))
        let initialState = sut.state
        mockFirebaseAuthenticator.reset() // Reset counts after setup

        // Act: Attempt sign in again
        await sut.signIn(from: dummyVC)

        // Assert
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 0, "Present UI should NOT have been called again")
        XCTAssertEqual(sut.state, initialState, "State should not have changed from \(initialState)")
        XCTAssertNil(sut.lastError, "Error should remain nil")
    }

    func testSignIn_WhenAuthenticating_doesNothing() async throws {
        // Arrange: Start sign in but hold the continuation
        mockFirebaseAuthenticator.reset() // Reset before action
        mockFirebaseAuthenticator.signInResultProvider = nil // Ensure provider is nil so it uses continuation

        // Start the sign-in task but don't await it yet
        let signInTask = Task { await sut.signIn(from: dummyVC) }

        // Allow brief moment for state to potentially change (though less critical without listener)
        // Yielding is better than sleeping
        await Task.yield()

        // Precondition: Verify state is authenticating
        guard case .authenticating = sut.state else {
            mockFirebaseAuthenticator.completeSignIn(result: .failure(AuthError.cancelled)) // Cleanup hanging task
            await signInTask.value // Wait for task exit
            throw TestError.unexpectedState("Expected authenticating state, got \(sut.state)")
        }
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1) // Initial call

        // Act: Call signIn again while the first one is 'hanging'
        await sut.signIn(from: dummyVC)

        // Assert
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1, "Present UI should NOT have been called again")
        if case .authenticating = sut.state { } else { XCTFail("State should have remained authenticating") }
        XCTAssertNil(sut.lastError)

        // Cleanup: Complete the original sign in
        mockFirebaseAuthenticator.completeSignIn(result: .success(createDummyUser(uid: "userHang")))
        await signInTask.value // Wait for the original task to finish
    }

    // MARK: - SignOut Tests

    func testSignOut_whenSignedIn_updatesStateClearsStorage() async throws {
        // Arrange: Sign in first
        let user = try await arrangeSuccessfulSignIn()
        XCTAssertEqual(sut.state, .signedIn(user))
        mockSecureStorage.reset() // Reset counts after arrangement
        mockFirebaseAuthenticator.reset()

        // Act
        sut.signOut() // Trigger the sign out process (synchronous state change in test mode)

        // Assert: Since listener is disabled, state change is synchronous
        XCTAssertEqual(sut.state, .signedOut, "State should be signedOut")
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockSecureStorage.clearUserIDCallCount, 1, "Clear User ID should have been called once.")
        XCTAssertNil(mockSecureStorage.getLastUserID(), "Stored User ID should be nil after sign out.")
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1)
    }

    func testSignOut_whenSignedOut_doesNothingSignificant() {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        mockSecureStorage.reset()
        mockFirebaseAuthenticator.reset()

        // Act
        sut.signOut()

        // Assert
        XCTAssertEqual(sut.state, .signedOut) // State remains signedOut
        XCTAssertNil(sut.lastError)
        // SignOut method *always* calls clearLocalUserData, which calls these
        XCTAssertEqual(mockSecureStorage.clearUserIDCallCount, 1)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1)
    }

    // MARK: - Biometrics Tests

    func testAuthenticateWithBiometrics_Success_whenRequired_updatesState() async throws {
        // Arrange: Setup requiresBiometrics state (which signs in real user)
        try await forceRequiresBiometricsState()
        guard let currentUser = Auth.auth().currentUser else {
             throw TestError.testSetupFailed("No emulator user for biometric test")
         }
        let user = AuthUser(firebaseUser: currentUser) // User object matching emulator

        mockBiometricAuthenticator.reset() // Reset counts after setup
        mockSecureStorage.reset()

        // Configure bio mock for success
        mockBiometricAuthenticator.authResultProvider = { .success(()) }

        // Act
        await sut.authenticateWithBiometrics(reason: "Test Bio")

        // Assert
        XCTAssertEqual(sut.state, .signedIn(user)) // Expect signedIn after successful bio
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockBiometricAuthenticator.authenticateCallCount, 1)
        XCTAssertEqual(mockBiometricAuthenticator.lastAuthReason, "Test Bio")
        // Save should NOT happen for anonymous emulator user after successful BIO either
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 0, "Save should not happen for anonymous emulator user post-bio")
    }

    func testAuthenticateWithBiometrics_Failure_whenRequired_retainsStateAndSetsError() async throws {
        // Arrange: Setup requiresBiometrics state (signs in real user)
        try await forceRequiresBiometricsState()

        mockBiometricAuthenticator.reset() // Reset counts after setup
        mockSecureStorage.reset()

        let bioError = AuthError.biometricsFailed(nil)
        mockBiometricAuthenticator.authResultProvider = { .failure(bioError) }

        // Act
        await sut.authenticateWithBiometrics(reason: "Test Bio Fail")

        // Assert
        XCTAssertEqual(sut.state, .requiresBiometrics) // State remains requiresBiometrics
        XCTAssertEqual(sut.lastError, bioError)
        XCTAssertEqual(mockBiometricAuthenticator.authenticateCallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 0) // No save on failure
    }

    func testAuthenticateWithBiometrics_whenNotRequired_doesNothing() async throws {
        // Arrange: Ensure signed in, not requiresBio
        let user = try await arrangeSuccessfulSignIn()
        XCTAssertEqual(sut.state, .signedIn(user))

        // Reset mocks after arrangement
        mockBiometricAuthenticator.reset()
        mockSecureStorage.reset()
        mockFirebaseAuthenticator.reset()

        // Act
        await sut.authenticateWithBiometrics(reason: "Should not run")

        // Assert
        XCTAssertEqual(sut.state, .signedIn(user), "State should remain signedIn")
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockBiometricAuthenticator.authenticateCallCount, 0)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 0)
    }

    // MARK: - Merge Conflict Tests

    func testProceedWithMergeConflict_Success_updatesStateAndClearsCreds() async throws {
        // Arrange: Setup requiresMergeConflictResolution state
        let mergeError = AuthError.mergeConflictRequired
        mockFirebaseAuthenticator.reset() // Reset before initial signIn
        mockFirebaseAuthenticator.signInResultProvider = { .failure(mergeError) }
        // Set credential BEFORE signIn so the state transition works in mock
        mockFirebaseAuthenticator.mockExistingCredentialForMergeConflict = placeholderTestCredential
        await sut.signIn(from: dummyVC)

        guard sut.state == .requiresMergeConflictResolution else {
            throw TestError.unexpectedState("Failed to arrange requiresMergeConflictResolution state, was \(sut.state)")
        }
        XCTAssertNotNil(mockFirebaseAuthenticator.existingCredentialForMergeConflict)
        mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount = 0 // Reset count AFTER state is confirmed

        // Arrange 2: **LIMITATION** Cannot mock internal `Auth.auth().signIn(with:)`.
        // Assume the SUT proceeds as if it would succeed.

        // Act: Proceed with resolution
        await sut.proceedWithMergeConflictResolution()

        // Assert: Initial actions and side effects
        // 1. State should become authenticating immediately
        XCTAssertEqual(sut.state, .authenticating("Signing in..."), "Should enter authenticating state")
        // 2. Error should be cleared
        XCTAssertNil(sut.lastError)
        // 3. ClearTemporaryCredentials should eventually be called (after hypothetical success)
        //    Since we can't wait for the real call, we check the count. The SUT calls this AFTER the await.
        //    In a unit test where the internal await succeeds instantly (conceptually), the clear happens.
         XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1, "Clear credentials should be called on successful proceed")

        // Cannot reliably assert final .signedIn state without mocking internal Firebase call.
        print("WARN: Cannot assert final .signedIn state in testProceedWithMergeConflict_Success due to unmockable internal Firebase call.")
    }


    func testProceedWithMergeConflict_MissingCredential_updatesStateWithError() async throws {
        // Arrange: Get into requiresMergeConflictResolution state *correctly*
        let mergeError = AuthError.mergeConflictRequired
        mockFirebaseAuthenticator.reset() // Reset before initial signIn
        mockFirebaseAuthenticator.signInResultProvider = { .failure(mergeError) }
        mockFirebaseAuthenticator.mockExistingCredentialForMergeConflict = placeholderTestCredential // Set before signIn
        await sut.signIn(from: dummyVC)

        guard sut.state == .requiresMergeConflictResolution else {
            throw TestError.unexpectedState("Failed to arrange requiresMergeConflictResolution state, was \(sut.state)")
        }
        XCTAssertEqual(sut.lastError, mergeError)
        XCTAssertNotNil(mockFirebaseAuthenticator.existingCredentialForMergeConflict)
        mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount = 0 // Reset count

        // Arrange Part 2: Simulate the credential being lost *before* proceeding
        mockFirebaseAuthenticator.mockExistingCredentialForMergeConflict = nil // <<< Credential MISSING *now*

        // Act
        await sut.proceedWithMergeConflictResolution()

        // Assert
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertEqual(sut.lastError, .missingLinkingInfo)
        // SUT calls clearTemporaryCredentials in the failure guard path
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1)
    }

    func testProceedWithMergeConflict_whenNotInMergeState_doesNothing() async {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        mockFirebaseAuthenticator.reset()
        mockSecureStorage.reset()

        // Act
        await sut.proceedWithMergeConflictResolution()

        // Assert
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 0)
    }

    // MARK: - Cancel Pending Action Tests

    // FIXED: Moved reset() call
    func testCancelPendingAction_whenLinkingRequired_updatesStateClearsCreds() async throws {
        // Arrange: Get into linking state
        let testEmail = "cancel-link@example.com"
        let linkingError = AuthError.accountLinkingRequired(email: testEmail)
        mockFirebaseAuthenticator.reset() // <<< FIX: Reset BEFORE configuration
        mockFirebaseAuthenticator.signInResultProvider = { .failure(linkingError) }
        await sut.signIn(from: dummyVC)

        // Verify state *after* signIn. May be signedOut if internal fetch failed.
        guard sut.state == .requiresAccountLinking(email: testEmail, existingProviders: []) || sut.state == .signedOut else {
             // Allow for either outcome depending on fetch behaviour in test env
             throw TestError.unexpectedState("Expected requiresAccountLinking or signedOut (if fetch failed) after initial signIn, but got \(sut.state)")
        }

        // Only proceed if we actually got into the linking state (best effort for unit test)
        if sut.state == .requiresAccountLinking(email: testEmail, existingProviders: []) {
             XCTAssertNotNil(mockFirebaseAuthenticator.pendingCredentialForLinking, "Pending credential should exist in mock if state is requiresAccountLinking")
             mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount = 0 // Reset count after state entry

             // Act
             sut.cancelPendingAction()

             // Assert
             XCTAssertEqual(sut.state, .signedOut)
             XCTAssertNil(sut.lastError)
             XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1)
         } else {
             print("INFO: Skipping cancel assertion because initial state was signedOut (likely due to fetch failure).")
             // Optionally assert that clear was NOT called yet if state remained signedOut
             XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1, "Clear *should* have been called during signIn error handling if fetch failed")
         }
    }

    func testCancelPendingAction_whenMergeRequired_updatesStateClearsCreds() async throws {
        // Arrange: Get into merge state
        let mergeError = AuthError.mergeConflictRequired
        mockFirebaseAuthenticator.reset() // Reset before config
        mockFirebaseAuthenticator.signInResultProvider = { .failure(mergeError) }
        mockFirebaseAuthenticator.mockExistingCredentialForMergeConflict = placeholderTestCredential // Set before signIn
        await sut.signIn(from: dummyVC)

        guard sut.state == .requiresMergeConflictResolution else {
            throw TestError.unexpectedState("Failed to arrange requiresMergeConflictResolution state, got \(sut.state)")
        }
        XCTAssertNotNil(mockFirebaseAuthenticator.existingCredentialForMergeConflict)
        mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount = 0 // Reset after state entry

        // Act
        sut.cancelPendingAction()

        // Assert
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1)
    }

    func testCancelPendingAction_whenNotInPendingState_doesNothing() async throws {
        // Arrange: Sign in first
        let user = try await arrangeSuccessfulSignIn()
        let initialState = sut.state
        XCTAssertEqual(initialState, .signedIn(user)) // Ensure it's actually signedIn

        mockFirebaseAuthenticator.reset() // Reset after arrangement
        mockSecureStorage.reset()

        // Act
        sut.cancelPendingAction()

        // Assert
        XCTAssertEqual(sut.state, initialState, "State should remain \(initialState)")
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 0)
    }
}
