import XCTest
import Combine
@testable import ASimpleAuthKit // Use @testable for internal access if needed (e.g., for User init)
import FirebaseAuthUI
import Firebase

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
    let placeholderTestCredential = EmailAuthProvider.credential(
        withEmail: "test@example.com",
        password: "fakepassword"
    )

    // Static flag to ensure configuration happens only once per test run
    private var firebaseConfigured = false
    private let authEmulatorHost = "localhost" // Or "127.0.0.1"
    private let authEmulatorPort = 9099

    // MARK: Lifecycle (Async)
    override func setUp() async throws {

        // --- Firebase Configuration & Emulator Setup ---
        if !firebaseConfigured {
            print("AuthServiceTests: Configuring Firebase and Auth Emulator for tests...")
            
            guard let fileURL = Bundle.module.url(forResource: "GoogleService-Info-Tests", withExtension: "plist") else {
                // Keep the same error message for now, just change the lookup method
                throw TestError.testSetupFailed("GoogleService-Info-Tests.plist not found in test bundle (Bundle.module).")
            }
            // And use the URL's path if needed by FirebaseOptions, or check if it accepts a URL directly
            guard let fileopts = FirebaseOptions(contentsOfFile: fileURL.path) else { // Use fileURL.path
                 throw TestError.testSetupFailed("Could not load FirebaseOptions from GoogleService-Info-Tests.plist.")
            }
            

            // Configure only if no default app exists (safer)
            if FirebaseApp.app() == nil {
                FirebaseApp.configure(options: fileopts)
                print("AuthServiceTests: FirebaseApp configured with test options.")
            } else {
                print("AuthServiceTests: FirebaseApp already configured.")
            }


            // 2. Point Auth to the Emulator
            Auth.auth().useEmulator(withHost: authEmulatorHost, port: authEmulatorPort)
            print("AuthServiceTests: FirebaseAuth configured to use emulator at \(authEmulatorHost):\(authEmulatorPort)")

            firebaseConfigured = true
            print("AuthServiceTests: One-time Firebase test setup complete.")
        }
        // --- End Firebase Configuration ---


        // --- Your existing mock setup ---
        cancellables = []
        dummyVC = DummyViewController()
        config = AuthConfig(providers: []) // Default config
        mockSecureStorage = MockSecureStorage(accessGroup: config.keychainAccessGroup)
        mockBiometricAuthenticator = MockBiometricAuthenticator()
        mockFirebaseAuthenticator = MockFirebaseAuthenticator(config: config, secureStorage: mockSecureStorage)

        // AuthService initialization MUST happen *after* FirebaseApp.configure()
        // and preferably after useEmulator()
        sut = AuthService(
            config: config,
            secureStorage: mockSecureStorage,
            firebaseAuthenticator: mockFirebaseAuthenticator,
            biometricAuthenticator: mockBiometricAuthenticator
        )
        print("AuthServiceTests: SUT initialized.")
        // --- End mock setup ---
    }
    override func tearDown() async throws {
        sut = nil
        mockFirebaseAuthenticator = nil
        mockBiometricAuthenticator = nil
        mockSecureStorage = nil
        config = nil
        cancellables = nil
        dummyVC = nil
    }

    // MARK: - Helper Methods

    /// Helper to perform a standard successful sign-in to arrange state.
    @discardableResult
    private func arrangeSuccessfulSignIn(user: AuthUser = createDummyUser()) async throws -> AuthUser {
        mockFirebaseAuthenticator.signInResultProvider = { .success(user) }
        await sut.signIn(from: dummyVC)

        // Wait for state to potentially settle (listener might run)
        try await Task.sleep(nanoseconds: 150_000_000) // Adjust if needed

        // Verify state became signedIn or requiresBiometrics (depending on stored user)
        guard sut.state == .requiresBiometrics || { // Check if it IS .requiresBiometrics OR...
            if case .signedIn = sut.state { // ...check if it IS a .signedIn case (ignoring the associated user)
                return true // If it's .signedIn, the guard condition passes
            } else {
                return false
            }
        }() else { // If NEITHER .requiresBiometrics NOR .signedIn(...)
            throw TestError.unexpectedState("Expected signedIn or requiresBiometrics after sign-in, got \(sut.state)")
        }

        // If state became requiresBiometrics, update storage mock to reflect reality
        if sut.state == .requiresBiometrics {
            mockSecureStorage.storage["\(mockSecureStorage.service)-lastUserID"] = user.uid
        }
        mockFirebaseAuthenticator.reset() // Reset calls before next action
        mockSecureStorage.saveUserIDCallCount = 0 // Reset this specifically if needed
        return user
    }

    /// Helper to simulate conditions leading to requiresBiometrics state
    private func arrangeRequiresBiometricsState(user: AuthUser = createDummyUser()) async throws {
        mockSecureStorage.storage["\(mockSecureStorage.service)-lastUserID"] = user.uid
        mockBiometricAuthenticator.mockIsAvailable = true
        try await arrangeSuccessfulSignIn(user: user) // Sign in the matching user

        // Verify state is now requiresBiometrics
        guard sut.state == .requiresBiometrics else {
            throw TestError.unexpectedState("Expected requiresBiometrics state, got \(sut.state)")
        }
        // Reset counts for the actual test action
        mockBiometricAuthenticator.authenticateCallCount = 0
        mockSecureStorage.saveUserIDCallCount = 0
        mockSecureStorage.clearUserIDCallCount = 0
    }

    // MARK: - Initialization Tests
    func testInit_initialStateIsSignedOut() {
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertNil(sut.lastError)
    }

    // MARK: - SignIn Tests

    func testSignIn_FromSignedOut_Success_updatesStateAndSavesUserID() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut) // Start signed out
        let expectedUser = createDummyUser(uid: "user123", isAnonymous: false)
        mockFirebaseAuthenticator.signInResultProvider = { .success(expectedUser) }

        // Act
        await sut.signIn(from: dummyVC)
        try await Task.sleep(nanoseconds: 150_000_000) // Allow listener processing

        // Assert
        // Assumes bio not available or no match, so ends in .signedIn
        XCTAssertEqual(sut.state, .signedIn(expectedUser))
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 1) // Saved by checkBiometrics
        XCTAssertEqual(mockSecureStorage.lastSavedUserID, "user123")
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 0)
    }

    func testSignIn_FromSignedOut_SuccessAnonymous_updatesStateDoesNotSaveUserID() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        let expectedUser = createDummyUser(uid: "anonUser", isAnonymous: true)
        mockFirebaseAuthenticator.signInResultProvider = { .success(expectedUser) }

        // Act
        await sut.signIn(from: dummyVC)
        try await Task.sleep(nanoseconds: 150_000_000)

        // Assert
        XCTAssertEqual(sut.state, .signedIn(expectedUser))
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 0) // Not saved for anon
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 0)
    }

    func testSignIn_FromRequiresBiometrics_Success_updatesStateToRequiresBiometrics() async throws {
        // Arrange: Setup requiresBiometrics state first
        let user = createDummyUser(uid: "bioUser")
        try await arrangeRequiresBiometricsState(user: user) // This performs the initial sign-in
        mockFirebaseAuthenticator.reset() // Reset after setup
        mockSecureStorage.saveUserIDCallCount = 0
        mockSecureStorage.getLastUserIDCallCount = 0

        // Act: Sign in again (e.g., user chose different method instead of bio)
        mockFirebaseAuthenticator.signInResultProvider = { .success(user) } // Sign in as the same user
        await sut.signIn(from: dummyVC)
        try await Task.sleep(nanoseconds: 150_000_000) // Allow listener processing

        // Assert: Should end up back in requiresBiometrics because user matches stored and bio available
        XCTAssertEqual(sut.state, .requiresBiometrics)
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1) // SignIn was called
        // Save shouldn't happen again if user already matched
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 0)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 0)
    }


    func testSignIn_Cancelled_updatesStateAndClearsCredentials() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        mockFirebaseAuthenticator.signInResultProvider = { .failure(AuthError.cancelled) }

        // Act
        await sut.signIn(from: dummyVC)

        // Assert
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertEqual(sut.lastError, .cancelled)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 0)
    }

    func testSignIn_GenericFirebaseError_updatesStateAndClearsCredentials() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        let firebaseError = AuthError.firebaseAuthError(.init(code: 1, domain: "test", message: "Firebase failed"))
        mockFirebaseAuthenticator.signInResultProvider = { .failure(firebaseError) }

        // Act
        await sut.signIn(from: dummyVC)

        // Assert
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertEqual(sut.lastError, firebaseError)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 0)
    }

    func testSignIn_AccountLinkingRequired_updatesStateIfFetchSucceeds() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        let testEmail = "link@example.com"
        let linkingError = AuthError.accountLinkingRequired(email: testEmail)
        mockFirebaseAuthenticator.signInResultProvider = { .failure(linkingError) }
        mockFirebaseAuthenticator.mockPendingCredentialForLinking = placeholderTestCredential
        // **Limitation:** Cannot mock `Auth.auth().fetchSignInMethods`. Test assumes it succeeds.
        // To test failure path, need more advanced mocking or integration tests.

        // Act
        await sut.signIn(from: dummyVC)

        // Assert (Assuming fetchSignInMethods hypothetically succeeds)
        if case .requiresAccountLinking(let email, _) = sut.state {
            XCTAssertEqual(email, testEmail)
        } else {
            // If fetch *actually* fails (which it will without mocks), state reverts.
            // This assertion might fail without Firebase mocking.
            XCTFail("State should be requiresAccountLinking assuming fetch succeeds, but was \(sut.state)")
        }
        XCTAssertEqual(sut.lastError, linkingError)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        // Clear creds only happens if fetch fails and state reverts to signedOut
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 0, "Clear creds should NOT be called if fetch succeeds")
    }

    func testSignIn_AccountLinkingRequired_updatesStateToSignedOutIfFetchFails() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        let testEmail = "link@example.com"
        let linkingError = AuthError.accountLinkingRequired(email: testEmail)
        mockFirebaseAuthenticator.signInResultProvider = { .failure(linkingError) }
        mockFirebaseAuthenticator.mockPendingCredentialForLinking = placeholderTestCredential
        // **Reality Check:** The internal Auth.auth().fetchSignInMethods call *will* fail without network/mocks.

        // Act
        await sut.signIn(from: dummyVC)

        // Assert (Based on actual SUT behavior when fetch fails)
        XCTAssertEqual(sut.state, .signedOut, "State should revert to signedOut if fetch fails")
        XCTAssertNotNil(sut.lastError)
        if case .firebaseAuthError = sut.lastError {
            // Correct error type for fetch failure
        } else {
            XCTFail("Expected firebaseAuthError from fetch failure, got \(String(describing: sut.lastError))")
        }
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1, "Clear creds SHOULD be called if fetch fails")
    }


    func testSignIn_MergeConflictRequired_updatesStateDoesNotClearCredentials() async throws {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        let mergeError = AuthError.mergeConflictRequired
        mockFirebaseAuthenticator.signInResultProvider = { .failure(mergeError) }
        mockFirebaseAuthenticator.mockExistingCredentialForMergeConflict = placeholderTestCredential

        // Act
        await sut.signIn(from: dummyVC)

        // Assert
        XCTAssertEqual(sut.state, .requiresMergeConflictResolution)
        XCTAssertEqual(sut.lastError, mergeError)
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 0)
    }

    func testSignIn_WhenAlreadySignedIn_doesNothing() async throws {
        // Arrange: Get into signedIn state first
        let user = try await arrangeSuccessfulSignIn()
        mockFirebaseAuthenticator.reset() // Reset calls before next action

        // Act: Attempt sign in again
        await sut.signIn(from: dummyVC)

        // Assert
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 0, "Present UI should NOT have been called again")
        // State might be signedIn(user) or requiresBiometrics depending on initial setup/checks
        if sut.state != .signedIn(user) && sut.state != .requiresBiometrics {
            XCTFail("State should have remained signedIn or requiresBiometrics, but was \(sut.state)")
        }
        XCTAssertNil(sut.lastError, "Error should remain nil")
    }

    func testSignIn_WhenAuthenticating_doesNothing() async throws {
        // Arrange: Start sign in but hold the continuation
        let initialUser = createDummyUser(uid: "userHang")
        mockFirebaseAuthenticator.signInResultProvider = nil // Ensure provider is nil so it uses continuation
        let signInTask = Task { await sut.signIn(from: dummyVC) }
        try await Task.sleep(nanoseconds: 100_000_000) // Allow time to enter authenticating state

        // Precondition
        guard case .authenticating = sut.state else {
            mockFirebaseAuthenticator.completeSignIn(result: Result<AuthUser, Error>.failure(AuthError.cancelled)) // Cleanup continuation
            await signInTask.value // Wait for task exit
            throw TestError.unexpectedState("Expected authenticating state, got \(sut.state)")
        }
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 1)
        mockFirebaseAuthenticator.presentSignInUICallCount = 0 // Reset count

        // Act: Call signIn again
        await sut.signIn(from: dummyVC)

        // Assert
        XCTAssertEqual(mockFirebaseAuthenticator.presentSignInUICallCount, 0, "Present UI should NOT have been called again")
        if case .authenticating = sut.state { } else { XCTFail("State should have remained authenticating") }
        XCTAssertNil(sut.lastError)

        // Cleanup
        mockFirebaseAuthenticator.completeSignIn(result: .success(initialUser)) // Complete the original sign in
        await signInTask.value
    }

    // MARK: - SignOut Tests

    func testSignOut_whenSignedIn_updatesStateClearsStorage() async throws {
        // Arrange: Sign in first
        let user = try await arrangeSuccessfulSignIn()
        // State could be signedIn or requiresBiometrics, both are valid signed-in states for sign out
        mockSecureStorage.clearUserIDCallCount = 0 // Reset count

        // Create an expectation for the state change
        let expectation = XCTestExpectation(description: "Wait for AuthService state to become signedOut")

        // Subscribe to state changes to fulfill the expectation
        var cancellable: AnyCancellable?
        cancellable = sut.statePublisher
            .sink { state in
            if state == .signedOut {
                expectation.fulfill()
                cancellable?.cancel() // Optional: Cancel subscription once fulfilled
            }
        }

        // Act
        sut.signOut() // Trigger the sign out process

        // Assert: Wait for the expectation to be fulfilled
        // Use the async version of wait for expectations in an async test function
        await fulfillment(of: [expectation], timeout: 2.0) // Adjust timeout if needed

        // Clean up cancellable just in case timeout occurred before fulfillment
        cancellable?.cancel()

        // Assert final state and side effects *after* waiting
        XCTAssertEqual(sut.state, .signedOut, "State should be signedOut after waiting for expectation.")
        XCTAssertEqual(mockSecureStorage.clearUserIDCallCount, 1, "Clear User ID should have been called once.")
        XCTAssertNil(mockSecureStorage.storage["\(mockSecureStorage.service)-lastUserID"], "Stored User ID should be nil after sign out.")
    }

    func testSignOut_whenSignedOut_doesNothing() {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut)
        mockSecureStorage.reset()

        // Act
        sut.signOut()

        // Assert
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockSecureStorage.clearUserIDCallCount, 0)
    }

    // MARK: - Biometrics Tests

    func testAuthenticateWithBiometrics_Success_whenRequired_updatesState() async throws {
        // Arrange: Setup requiresBiometrics state
        let user = createDummyUser(uid: "bioUser")
        try await arrangeRequiresBiometricsState(user: user)
        mockBiometricAuthenticator.authResultProvider = { .success(()) }
        // **Limitation:** Assumes internal `Auth.auth().currentUser` check passes.

        // Act
        await sut.authenticateWithBiometrics(reason: "Test Bio")

        // Assert
        XCTAssertEqual(sut.state, .signedIn(user)) // Expect signedIn after successful bio
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockBiometricAuthenticator.authenticateCallCount, 1)
        XCTAssertEqual(mockBiometricAuthenticator.lastAuthReason, "Test Bio")
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 1) // Save happens post-success
    }

    func testAuthenticateWithBiometrics_Failure_whenRequired_retainsStateAndSetsError() async throws {
        // Arrange: Setup requiresBiometrics state
        try await arrangeRequiresBiometricsState()
        mockBiometricAuthenticator.authResultProvider = { .failure(.biometricsFailed(nil)) }
        // **Limitation:** Assumes internal `Auth.auth().currentUser` guard check passes.

        // Act
        await sut.authenticateWithBiometrics(reason: "Test Bio Fail")

        // Assert
        XCTAssertEqual(sut.state, .requiresBiometrics) // State remains requiresBiometrics
        XCTAssertEqual(sut.lastError, .biometricsFailed(nil))
        XCTAssertEqual(mockBiometricAuthenticator.authenticateCallCount, 1)
    }

    func testAuthenticateWithBiometrics_whenNotRequired_doesNothing() async throws {
        // Arrange: Ensure signed in, not requiresBio
        try await arrangeSuccessfulSignIn()
        guard case .signedIn = sut.state else {
            throw TestError.unexpectedState("Should be signedIn for this test, was \(sut.state)")
        }
        mockBiometricAuthenticator.reset()

        // Act
        await sut.authenticateWithBiometrics(reason: "Should not run")

        // Assert
        if case .signedIn = sut.state { } else { XCTFail("State should remain signedIn") }
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockBiometricAuthenticator.authenticateCallCount, 0)
    }

    // MARK: - Merge Conflict Tests (Limitations apply)

    func testProceedWithMergeConflict_Success_InitiatesAuthAndClearsCreds() async throws {
        // Arrange: Simulate requiresMergeConflictResolution state
        XCTAssertEqual(sut.state, .signedOut) // Start signed out
        let mergeError = AuthError.mergeConflictRequired
        mockFirebaseAuthenticator.signInResultProvider = { .failure(mergeError) } // Trigger merge state via sign-in error
        mockFirebaseAuthenticator.mockExistingCredentialForMergeConflict = placeholderTestCredential
        await sut.signIn(from: dummyVC)
        guard sut.state == .requiresMergeConflictResolution else {
            throw TestError.unexpectedState("Expected requiresMergeConflictResolution, got \(sut.state)")
        }
        mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount = 0 // Reset count

        // Act: Proceed with resolution
        await sut.proceedWithMergeConflictResolution()
        // **Limitation:** Cannot mock `Auth.auth().signIn(with:)`.

        // Assert: Initial state change and side effects assuming success
        XCTAssertEqual(sut.state, .authenticating("Signing in..."))
        try await Task.sleep(nanoseconds: 150_000_000) // Allow time for async SUT logic

        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1)
        // Cannot assert final state without Firebase mock
        // Cannot reliably assert saveUserIDCallCount without Firebase mock
    }

    func testProceedWithMergeConflict_MissingCredential_updatesStateWithError() async throws {
        // Arrange: Get into requiresMergeConflictResolution state *correctly*
        XCTAssertEqual(sut.state, .signedOut)
        let mergeError = AuthError.mergeConflictRequired
        let initialCredential = placeholderTestCredential // Use a placeholder

        mockFirebaseAuthenticator.signInResultProvider = { .failure(mergeError) }
        // Set the credential BEFORE signIn so the state transition works
        mockFirebaseAuthenticator.mockExistingCredentialForMergeConflict = initialCredential
        await sut.signIn(from: dummyVC)

        // Verify we are now in the correct state
        guard sut.state == .requiresMergeConflictResolution else {
            throw TestError.unexpectedState("Expected requiresMergeConflictResolution after sign-in failure with credential, got \(sut.state)")
        }
        // State is correct, error should be mergeError from the sign-in
        XCTAssertEqual(sut.lastError, mergeError)
        mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount = 0 // Clear shouldn't happen on state entry

        // Arrange Part 2: Simulate the credential being lost *before* proceeding
        mockFirebaseAuthenticator.mockExistingCredentialForMergeConflict = nil // <<< Credential MISSING *now*

        // Act
        await sut.proceedWithMergeConflictResolution()

        // Assert
        XCTAssertEqual(sut.state, .signedOut) // State should revert
        XCTAssertEqual(sut.lastError, .missingLinkingInfo) // Error should indicate missing info
        // Check implementation: proceedWithMergeConflictResolution calls clearTemporaryCredentials in the guard failure path
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1)
    }

    func testProceedWithMergeConflict_whenNotInMergeState_doesNothing() async {
        // Arrange
        XCTAssertEqual(sut.state, .signedOut) // Start signed out
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

    func testCancelPendingAction_whenLinkingRequired_updatesStateClearsCreds() async throws {
        // Arrange: Get into linking state
        XCTAssertEqual(sut.state, .signedOut)
        let testEmail = "link@example.com"
        let linkingError = AuthError.accountLinkingRequired(email: testEmail)
        mockFirebaseAuthenticator.signInResultProvider = { .failure(linkingError) }
        mockFirebaseAuthenticator.mockPendingCredentialForLinking = placeholderTestCredential
        await sut.signIn(from: dummyVC) // Assume fetch succeeds hypothetically for state entry

        guard case .requiresAccountLinking = sut.state else {
            // If fetch *actually* failed, state would be signedOut. Skip test.
            throw XCTSkip("Skipping test - Cannot reliably enter requiresAccountLinking without Firebase fetch mock.")
        }
        mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount = 0 // Reset

        // Act
        sut.cancelPendingAction()

        // Assert
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1)
    }

    func testCancelPendingAction_whenMergeRequired_updatesStateClearsCreds() async throws {
        // Arrange: Get into merge state
        XCTAssertEqual(sut.state, .signedOut)
        let mergeError = AuthError.mergeConflictRequired
        mockFirebaseAuthenticator.signInResultProvider = { .failure(mergeError) }
        mockFirebaseAuthenticator.mockExistingCredentialForMergeConflict = placeholderTestCredential
        await sut.signIn(from: dummyVC)
        guard sut.state == .requiresMergeConflictResolution else {
            throw TestError.unexpectedState("Expected requiresMergeConflictResolution, got \(sut.state)")
        }
        mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount = 0 // Reset

        // Act
        sut.cancelPendingAction()

        // Assert
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1)
    }

    func testCancelPendingAction_whenNotInPendingState_doesNothing() async throws {
        // Arrange: Sign in first
        try await arrangeSuccessfulSignIn()
        guard case .signedIn = sut.state else { // Ensure signedIn, not requiresBio
            if sut.state == .requiresBiometrics { try await arrangeRequiresBiometricsState() } // Try to get to signedIn via bio auth
            guard case .signedIn = sut.state else { throw TestError.unexpectedState("Could not arrange signedIn state, was \(sut.state)") }
            return
        }

        mockFirebaseAuthenticator.reset()

        // Act
        sut.cancelPendingAction()

        // Assert
        if case .signedIn = sut.state { } else { XCTFail("State should remain signedIn") }
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 0)
    }
}
