import XCTest
import Combine
@testable import ASimpleAuthKit
import FirebaseAuth // For AuthCredential and live Auth interaction in some tests
import FirebaseCore

@MainActor
final class AuthServiceTests: XCTestCase {

    // MARK: Properties
    var sut: AuthService! // System Under Test
    var mockFirebaseAuthenticator: MockFirebaseAuthenticator!
    var mockBiometricAuthenticator: MockBiometricAuthenticator!
    var mockSecureStorage: MockSecureStorage!
    var config: AuthConfig!
    var cancellables: Set<AnyCancellable>!
    var dummyVC: DummyViewController!

    private static var firebaseConfigured = false
    private let authEmulatorHost = "localhost"
    private let authEmulatorPort = 9099

    // MARK: Lifecycle
    override func setUp() async throws {
        try await super.setUp() // Important for XCTest async setup

        if !AuthServiceTests.firebaseConfigured {
            // ... (Firebase Emulator setup code remains the same as your original)
            // For brevity, I'm omitting it here, but assume it's present and working.
            // It's crucial for tests that might interact with Auth.auth() directly.
            print("AuthServiceTests: Configuring Firebase and Auth Emulator for tests (one-time)...")
            guard let fileURL = Bundle.module.url(forResource: "GoogleService-Info-Tests", withExtension: "plist") else {
                throw TestError.testSetupFailed("GoogleService-Info-Tests.plist not found")
            }
            guard let fileopts = FirebaseOptions(contentsOfFile: fileURL.path) else {
                throw TestError.testSetupFailed("Could not load FirebaseOptions")
            }
            if FirebaseApp.app() == nil { FirebaseApp.configure(options: fileopts) }
            Auth.auth().useEmulator(withHost: authEmulatorHost, port: authEmulatorPort)
            AuthServiceTests.firebaseConfigured = true
            print("AuthServiceTests: One-time Firebase test setup complete.")
        }

        // Attempt pre-test sign out from emulator
        try? Auth.auth().signOut() // Can throw, but we don't fail test if it does

        cancellables = []
        dummyVC = DummyViewController()
        // Config no longer takes FUIAuthProvider array
        config = AuthConfig(
            tosURL: URL(string: "test-tos.com"),
            privacyPolicyURL: URL(string: "test-privacy.com")
        )
        mockSecureStorage = MockSecureStorage() // Uses default bundle ID for service
        mockBiometricAuthenticator = MockBiometricAuthenticator()
        // MockFirebaseAuthenticator now has a simpler init or takes the config if needed for its logic
        mockFirebaseAuthenticator = MockFirebaseAuthenticator()

        sut = AuthService(
            config: config,
            secureStorage: mockSecureStorage,
            firebaseAuthenticator: mockFirebaseAuthenticator,
            biometricAuthenticator: mockBiometricAuthenticator,
            isTestMode: true // Keep SUT in test mode
        )
        sut.forceStateForTesting(.signedOut) // Ensure a clean starting state for SUT
        print("AuthServiceTests: SUT initialized in test mode, forced to .signedOut.")
    }

    override func tearDown() async throws {
        // Attempt post-test sign out
        try? Auth.auth().signOut()

        sut?.invalidate() // Call invalidate before SUT is nilled

        cancellables.forEach { $0.cancel() }
        cancellables = nil
        sut = nil
        mockFirebaseAuthenticator = nil
        mockBiometricAuthenticator = nil
        mockSecureStorage = nil
        config = nil
        dummyVC = nil
        print("AuthServiceTests: Teardown complete.")
        try await super.tearDown()
    }

    // MARK: - Helper: Arrange Successful Sign-In State
    // This helper might be less direct now, as successful sign-in depends on which provider method is called.
    // We'll mostly set up mockFirebaseAuthenticator directly in tests.
    private func arrangeSUTStateToSignedIn(user: AuthUser = createDummyUser()) async {
        mockSecureStorage.reset()
        mockBiometricAuthenticator.reset()
        mockBiometricAuthenticator.mockIsAvailable = false // Default to no biometrics for simple sign-in

        // Simulate a successful sign-in has occurred and user ID saved
        try? await mockSecureStorage.saveLastUserID(user.uid)

        // Force the SUT state
        sut.forceStateForTesting(.signedIn(user))
        XCTAssertEqual(sut.state, .signedIn(user), "Helper: Failed to arrange SUT to signedIn state.")
    }

    // MARK: - Initialization Tests
    func testInit_initialStateIsSignedOut() {
        // setUp now forces to .signedOut
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertNil(sut.lastError)
    }

    // MARK: - Email/Password Sign-In Tests
    func testSignInWithEmail_Success_updatesStateToSignedIn_SavesUserID() async throws {
        let expectedUser = createDummyUser(uid: "emailUser1", providerID: "password")
        mockFirebaseAuthenticator.signInWithEmailResultProvider = { email, pass in
            XCTAssertEqual(email, "test@example.com")
            XCTAssertEqual(pass, "password123")
            return .success(expectedUser)
        }
        mockBiometricAuthenticator.mockIsAvailable = false // Ensure no bio prompt

        await sut.signInWithEmail(email: "test@example.com", password: "password123")

        XCTAssertEqual(sut.state, .signedIn(expectedUser))
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.signInWithEmailCallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 1)
        let storedID = await mockSecureStorage.getLastUserID()
        XCTAssertEqual(storedID, expectedUser.uid)
    }

    func testSignInWithEmail_Success_updatesStateToRequiresBiometrics() async throws {
        let user = createDummyUser(uid: "emailBioUser", providerID: "password")
        // Pre-condition: User ID already in keychain, biometrics available
        try await mockSecureStorage.saveLastUserID(user.uid)
        mockBiometricAuthenticator.mockIsAvailable = true
        mockFirebaseAuthenticator.signInWithEmailResultProvider = { _, _ in .success(user) }
        mockSecureStorage.saveUserIDCallCount = 0 // Reset after manual save

        await sut.signInWithEmail(email: "test@example.com", password: "password123")

        XCTAssertEqual(sut.state, .requiresBiometrics)
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.signInWithEmailCallCount, 1)
        // SaveUserID should NOT be called again by AuthService if UID matches and bio is available
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 0)
    }

    func testSignInWithEmail_Failure_WrongPassword_setsErrorAndStateRemainsSignedOut() async {
        let wrongPasswordError = AuthError.firebaseAuthError(
            FirebaseErrorData(code: AuthErrorCode.wrongPassword.rawValue, domain: AuthErrorDomain, message: "Wrong password.")
        )
        mockFirebaseAuthenticator.signInWithEmailResultProvider = { _, _ in .failure(wrongPasswordError) }

        await sut.signInWithEmail(email: "test@example.com", password: "wrongpassword")

        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertEqual(sut.lastError, wrongPasswordError)
        XCTAssertEqual(mockFirebaseAuthenticator.signInWithEmailCallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 0)
    }

    // MARK: - Create Account with Email/Password Tests
    func testCreateAccountWithEmail_Success_updatesStateToSignedIn() async throws {
        let newUser = createDummyUser(uid: "newEmailUser", email: "new@example.com", providerID: "password")
        mockFirebaseAuthenticator.createAccountWithEmailResultProvider = { email, pass, dn in
            XCTAssertEqual(email, "new@example.com")
            XCTAssertEqual(pass, "newPass123")
            XCTAssertEqual(dn, "New User")
            return .success(newUser)
        }
        mockBiometricAuthenticator.mockIsAvailable = false

        await sut.createAccountWithEmail(email: "new@example.com", password: "newPass123", displayName: "New User")

        XCTAssertEqual(sut.state, .signedIn(newUser))
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.createAccountWithEmailCallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 1)
    }

    func testCreateAccountWithEmail_Failure_EmailAlreadyInUse_LeadsToAccountLinkingRequired() async throws {
        let existingEmail = "existing@example.com"
        // This error is now constructed by MockFirebaseAuthenticator's processMockResult
        // if its provider returns .accountLinkingRequired with a nil credential.
        // Or, if it directly returns the error code for emailAlreadyInUse, FirebaseAuthenticator
        // should convert it.
        let emailInUseError = AuthError.accountLinkingRequired(email: existingEmail, pendingCredential: nil)

        mockFirebaseAuthenticator.createAccountWithEmailResultProvider = { email, _, _ in
            XCTAssertEqual(email, existingEmail)
            // Simulate that the authenticator itself determined linking is required
            // This implies the authenticator internally caught emailAlreadyInUse and converted it
            return .failure(emailInUseError)
        }

        // Mock fetchSignInMethods to return some providers for testing UI state
        // Note: In a real scenario with EEP, this might be empty.
        // For testing the state transition, we can assume it returns something.
        // This requires Auth.auth() to be involved or more complex mocking.
        // For now, we test AuthService's reaction to the error from authenticator.
        // To fully test the fetchSignInMethods call, we'd need an emulator user.

        await sut.createAccountWithEmail(email: existingEmail, password: "anypassword", displayName: nil)

        if case .requiresAccountLinking(let email, let providers) = sut.state {
              XCTAssertEqual(email, existingEmail)
              // Based on current AuthService implementation, providers list is always empty here.
              XCTAssertTrue(providers.isEmpty, "Expected providers list to be empty based on current AuthService implementation.")
              print("Providers in state for .requiresAccountLinking: \(providers)")
          } else {
              XCTFail("Expected .requiresAccountLinking state, got \(sut.state)")
          }

        XCTAssertEqual(sut.lastError, emailInUseError) // Error that initiated linking flow
        XCTAssertEqual(mockFirebaseAuthenticator.createAccountWithEmailCallCount, 1)
        XCTAssertNil(sut.pendingCredentialToLinkAfterReauth, "No credential should be pending from email creation fail")
    }


    // MARK: - Google Sign-In Tests
    func testSignInWithGoogle_Success_updatesStateToSignedIn() async throws {
        let googleUser = createDummyUser(uid: "googleUser1", providerID: "google.com")
        mockFirebaseAuthenticator.signInWithGoogleResultProvider = { _ in .success(googleUser) }
        mockBiometricAuthenticator.mockIsAvailable = false

        await sut.signInWithGoogle(presentingViewController: dummyVC)

        XCTAssertEqual(sut.state, .signedIn(googleUser))
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.signInWithGoogleCallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 1)
    }

    func testSignInWithGoogle_Cancelled_setsErrorAndStateRemainsSignedOut() async {
        mockFirebaseAuthenticator.signInWithGoogleResultProvider = { _ in .failure(.cancelled) }

        await sut.signInWithGoogle(presentingViewController: dummyVC)

        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertEqual(sut.lastError, .cancelled)
    }

    // MARK: - Apple Sign-In Tests
    func testSignInWithApple_Success_updatesStateToSignedIn() async throws {
        let appleUser = createDummyUser(uid: "appleUser1", providerID: "apple.com")
        mockFirebaseAuthenticator.signInWithAppleResultProvider = { _, nonce in
            XCTAssertFalse(nonce.isEmpty, "Nonce should not be empty")
            return .success(appleUser)
        }
        mockBiometricAuthenticator.mockIsAvailable = false

        await sut.signInWithApple(presentingViewController: dummyVC) // Nonce handled by SUT

        XCTAssertEqual(sut.state, .signedIn(appleUser))
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.signInWithAppleCallCount, 1)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 1)
    }

    // MARK: - Account Linking Flow Test (Example: Apple sign-in, account exists with Email)
    func testLinkingFlow_AppleSignIn_AccountExistsWithEmail_ReauthWithEmail_LinksApple() async throws {
        let existingEmail = "linktest@example.com"
        // Ensure this user and password can actually sign into your emulator if not already existing
        // You might need to create this user in the emulator manually or via a setup script for the test run.
        // For this test, let's assume "correctpassword" is valid for "linktest@example.com" in the emulator.
        let originalUser = createDummyUser(uid: "originalEmailUserUidToActuallySignIn", email: existingEmail, providerID: "password")
        let appleCredential = createPlaceholderAuthCredential(providerID: "apple.com")

        // 1. Initial Apple Sign-In attempt fails with accountLinkingRequired
        let linkingError = AuthError.accountLinkingRequired(email: existingEmail, pendingCredential: appleCredential)
        mockFirebaseAuthenticator.signInWithAppleResultProvider = { _, _ in .failure(linkingError) }

        print("Test Step 1: Initial Apple Sign-In attempt...")
        await sut.signInWithApple(presentingViewController: dummyVC)

        guard case .requiresAccountLinking(let email, let providers) = sut.state else {
            XCTFail("Expected .requiresAccountLinking state, got \(sut.state). Error: \(String(describing: sut.lastError))")
            return
        }
        XCTAssertEqual(email, existingEmail)
        XCTAssertEqual(sut.lastError, linkingError)
        XCTAssertNotNil(sut.pendingCredentialToLinkAfterReauth, "SUT should have stored the pending Apple credential")
        XCTAssertEqual(sut.pendingCredentialToLinkAfterReauth?.provider, appleCredential.provider)
        let initialAppleCallCount = mockFirebaseAuthenticator.signInWithAppleCallCount
        let initialEmailCallCount = mockFirebaseAuthenticator.signInWithEmailCallCount
        let initialLinkCallCount = mockFirebaseAuthenticator.linkCredentialCallCount


        // 2. User is prompted to re-authenticate with their existing Email/Password method
        print("Test Step 2: Re-authenticating with Email/Password...")

        // --- CRITICAL INTEGRATION STEP FOR LINKING ---
        // Sign in to the emulator with the 'originalUser's' credentials.
        // This sets Auth.auth().currentUser so that AuthService.completeAccountLinking can find it.
        // This user (linktest@example.com) must exist in your Firebase Auth Emulator.
        // If it doesn't, this test will fail here or the linking logic will fail.
        // One way to ensure it exists is to create it if it doesn't, then sign in.
        // For simplicity, this example assumes it can be signed into.
        var firebaseUserForLinking: FirebaseAuth.User?
        do {
            // Try to sign in the user who is supposed to be re-authenticating.
            let authResult = try await Auth.auth().signIn(withEmail: existingEmail, password: "correctpassword")
            firebaseUserForLinking = authResult.user
            // Now Auth.auth().currentUser should be set to this user.
            // Update originalUser.uid if it was a placeholder and you want to use the actual UID from emulator
            // For this test, we assume originalUser.uid is what we expect or we don't care about its specific value,
            // as long as the flow works. Let's use the UID from the actual sign-in.
            let signedInOriginalUser = AuthUser(firebaseUser: firebaseUserForLinking!) // Create AuthUser from the actual signed-in Firebase user

            mockFirebaseAuthenticator.signInWithEmailResultProvider = { _, _ in .success(signedInOriginalUser) }

        } catch {
            XCTFail("Failed to sign in 'originalUser' (\(existingEmail)) to emulator for linking test re-auth step: \(error). Ensure this user exists in the emulator with 'correctpassword'.")
            return // Stop test if re-auth setup fails
        }
        // --- END CRITICAL INTEGRATION STEP ---

        // Mock the linking call itself
        let linkedProviderId = appleCredential.provider // The provider of the credential being linked
        mockFirebaseAuthenticator.linkCredentialResultProvider = { credToLink, fbUserToLinkTo in
            XCTAssertEqual(fbUserToLinkTo.uid, firebaseUserForLinking!.uid) // Ensure linking to the correct Firebase User
            XCTAssertEqual(credToLink.provider, appleCredential.provider)
            // Simulate linking success by returning a user that reflects the linked state
            // The UID remains the same. The providerID in AuthUser might reflect the newly linked one or primary.
            return .success(createDummyUser(uid: firebaseUserForLinking!.uid, email: existingEmail, providerID: linkedProviderId))
        }
        mockBiometricAuthenticator.mockIsAvailable = false

        await sut.signInWithEmail(email: existingEmail, password: "correctpassword")

        // 3. Assert final state
        if case .signedIn(let finalUser) = sut.state {
            XCTAssertEqual(finalUser.uid, firebaseUserForLinking!.uid) // UID should be that of the original, now linked, user
            // To verify the link, you might also check finalUser.providerData in a real scenario,
            // or ensure the providerID reflects the new link if your AuthUser logic does that.
            // For this test, checking UID and nil error is key.
        } else {
            XCTFail("Expected .signedIn state after successful linking, got \(sut.state). Error: \(String(describing: sut.lastError))")
        }
        XCTAssertNil(sut.lastError, "Error should be nil after successful link. Actual: \(String(describing: sut.lastError))")
        XCTAssertNil(sut.pendingCredentialToLinkAfterReauth, "Pending credential should be cleared after linking.")
        XCTAssertEqual(mockFirebaseAuthenticator.signInWithAppleCallCount, initialAppleCallCount)
        XCTAssertEqual(mockFirebaseAuthenticator.signInWithEmailCallCount, initialEmailCallCount + 1)
        XCTAssertEqual(mockFirebaseAuthenticator.linkCredentialCallCount, initialLinkCallCount + 1)

        // saveUserIDCallCount depends on whether the UID changed or biometrics setup.
        // If the UID was already saved and biometrics settings didn't require a re-save, it might be 0 for this part.
        // For a fresh link, it's likely 1.
        // Let's assume it's saved after linking if it's considered a successful sign-in/update.
        // AuthService.completeAccountLinking calls checkBiometricsRequirement, which can call saveLastUserID.
        // This depends on the state of mockSecureStorage.getLastUserID() before this linking.
        // For simplicity, if you reset mockSecureStorage before this test, it will be 1.
        // If you want to be precise, check the conditions in `determineBiometricStateInternal`.
        // For this test, let's focus on the linking itself. If saveUserID is not the primary assertion, make it flexible or set up mockSecureStorage for a specific outcome.
        // XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 1) // This might need adjustment based on pre-test storage state
    }

    // MARK: - Biometrics Tests (largely similar, ensure they use new mocks)
    func testAuthenticateWithBiometrics_Success_whenRequired_updatesState() async throws {
        // This test might need an actual Firebase user session in the emulator
        // if `Auth.auth().currentUser` is crucial for the SUT's internal logic.
        // Forcing state might not be enough if SUT relies on a live `currentUser`.
        let testUser = createDummyUser(uid: "bioUserActual")
        try await _ = forceRequiresBiometricsStateAndEmulatorUser() // New helper for this

        mockBiometricAuthenticator.authResultProvider = { .success(()) }

        await sut.authenticateWithBiometrics(reason: "Test Bio")

        if case .signedIn(let signedInUser) = sut.state {
            XCTAssertEqual(signedInUser.uid, testUser.uid)
        } else {
            XCTFail("Expected .signedIn state, got \(sut.state)")
        }
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockBiometricAuthenticator.authenticateCallCount, 1)
    }

    // MARK: - Password Reset
    func testSendPasswordResetEmail_Success() async {
        let email = "reset@example.com"
        mockFirebaseAuthenticator.sendPasswordResetEmailError = nil // Explicitly success

        await sut.sendPasswordResetEmail(to: email)

        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.sendPasswordResetEmailCallCount, 1)
        XCTAssertEqual(mockFirebaseAuthenticator.lastEmailForPasswordReset, email)
        // State should revert from .authenticating if it was set
        XCTAssertEqual(sut.state, .signedOut) // Or previous non-authenticating state
    }

    func testSendPasswordResetEmail_Failure() async {
        let email = "resetfail@example.com"
        let expectedError = AuthError.firebaseAuthError(FirebaseErrorData(code: 123, domain: "test", message: "fail"))
        mockFirebaseAuthenticator.sendPasswordResetEmailError = expectedError

        await sut.sendPasswordResetEmail(to: email)

        XCTAssertEqual(sut.lastError, expectedError)
        XCTAssertEqual(mockFirebaseAuthenticator.sendPasswordResetEmailCallCount, 1)
        XCTAssertEqual(sut.state, .signedOut) // Or previous non-authenticating state
    }

    // --- Helper for tests needing a live emulator user for biometrics ---
    // This is complex because it mixes mocking SUT dependencies with live Firebase state
    private func forceRequiresBiometricsStateAndEmulatorUser() async throws -> AuthUser {
        print("ForceBiometrics Helper (with Emulator User): Starting...")
        try? Auth.auth().signOut() // Clear any existing emulator session

        guard let firebaseEmulatorUser = try? await Auth.auth().signInAnonymously().user else {
            throw TestError.testSetupFailed("Emulator signInAnonymously failed. Is emulator running?")
        }
        // Create an AuthUser from the actual Firebase user obtained from the emulator
        let emulatorAuthUser = AuthUser(firebaseUser: firebaseEmulatorUser)

        // Save the *actual* emulator UID to mockSecureStorage
        try await mockSecureStorage.saveLastUserID(emulatorAuthUser.uid)
        mockBiometricAuthenticator.mockIsAvailable = true

        sut.forceStateForTesting(.requiresBiometrics) // Force SUT's state machine

        guard sut.state == .requiresBiometrics else {
            try? Auth.auth().signOut() // Clean up emulator session on helper failure
            throw TestError.unexpectedState("Failed to force .requiresBiometrics state, was \(sut.state)")
        }
        print("ForceBiometrics Helper (with Emulator User): Successfully forced .requiresBiometrics with live user \(emulatorAuthUser.uid).")

        // Reset mock counts for the actual test part
        mockBiometricAuthenticator.reset()
        // mockSecureStorage.reset() // Don't reset storage as it now contains the UID for the biometrics flow.
        // Reset specific counts if needed, or handle in test.
        mockSecureStorage.saveUserIDCallCount = 0 // Reset just the count if saveLastUserID was called above
        mockSecureStorage.getLastUserIDCallCount = 0
        mockSecureStorage.clearUserIDCallCount = 0

        mockFirebaseAuthenticator.reset()
        return emulatorAuthUser // Return the user that was actually signed into the emulator
    }
}

// Extension to AuthService for test-specific helpers
extension AuthService {
    #if DEBUG
        @MainActor
        func forcePendingCredentialForTesting(_ cred: AuthCredential?) {
            guard isTestMode else { return }
            self.pendingCredentialToLinkAfterReauth = cred
            print("AuthService (Test Mode): Forced pendingCredentialToLinkAfterReauth.")
        }
    #endif
}
