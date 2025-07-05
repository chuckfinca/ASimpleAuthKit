import XCTest
import Combine
@testable import ASimpleAuthKit
import FirebaseAuth
import FirebaseCore

@MainActor
final class AuthServiceTests: XCTestCase {

    var sut: AuthService!
    var mockFirebaseAuthenticator: MockFirebaseAuthenticator!
    var mockBiometricAuthenticator: MockBiometricAuthenticator!
    var mockSecureStorage: MockSecureStorage!
    var mockFirebaseAuthClient: MockFirebaseAuthClient!
    var config: AuthConfig!
    var cancellables: Set<AnyCancellable>!
    var dummyVC: DummyViewController!

    override class func setUp() {
        super.setUp()
        // Configure Firebase for the test suite. This is necessary because some
        // parts of the code (even within mocks) may interact with the global
        // FirebaseApp instance, triggering a crash if not configured.
        if FirebaseApp.app() == nil {
            // The "GoogleService-Info-Tests.plist" is included in the test target's resources.
            // Use `Bundle.module` which is the correct way to access resources in a Swift Package.
            guard let path = Bundle.module.path(forResource: "GoogleService-Info-Tests", ofType: "plist"),
            let options = FirebaseOptions(contentsOfFile: path) else {
                fatalError("Could not locate or parse GoogleService-Info-Tests.plist for testing.")
            }
            FirebaseApp.configure(options: options)
            print("FirebaseApp configured for test suite.")
        }
    }

    override func setUp() async throws {
        try await super.setUp()

        cancellables = []
        dummyVC = DummyViewController()
        config = AuthConfig()
        mockSecureStorage = MockSecureStorage()
        mockBiometricAuthenticator = MockBiometricAuthenticator()
        mockFirebaseAuthenticator = MockFirebaseAuthenticator()
        mockFirebaseAuthClient = MockFirebaseAuthClient()

        sut = AuthService(
            config: config,
            secureStorage: mockSecureStorage,
            firebaseAuthenticator: mockFirebaseAuthenticator,
            biometricAuthenticator: mockBiometricAuthenticator,
            firebaseAuthClient: mockFirebaseAuthClient,
            isTestMode: true
        )
        sut.forceStateForTesting(.signedOut)
    }

    override func tearDown() async throws {
        sut?.invalidate()
        sut = nil
        cancellables = nil
        dummyVC = nil
        config = nil
        mockSecureStorage = nil
        mockBiometricAuthenticator = nil
        mockFirebaseAuthenticator = nil
        mockFirebaseAuthClient = nil
        try await super.tearDown()
    }

    // MARK: - Auth State Listener Tests

    func testAuthStateListener_whenUserSignsInExternally_updatesStateToSignedIn() async throws {
        sut.isTestMode = false // Allow listener to react
        let firebaseUser = createDummyFirebaseUser(uid: "externalUser")
        let authUser = AuthUser(firebaseUser: firebaseUser)

        let expectation = XCTestExpectation(description: "State should update to .signedIn")
        sut.$state.dropFirst().sink { state in
            if state == .signedIn(authUser) {
                expectation.fulfill()
            }
        }.store(in: &cancellables)

        mockFirebaseAuthClient.simulateAuthStateChange(to: firebaseUser)

        await fulfillment(of: [expectation], timeout: 1.0)
        XCTAssertEqual(sut.state, .signedIn(authUser))
    }

    func testAuthStateListener_whenUserSignsOutExternally_updatesStateToSignedOutAndClearsData() async throws {
        sut.forceStateForTesting(.signedIn(createDummyAuthUser()))
        sut.isTestMode = false

        let expectation = XCTestExpectation(description: "State should update to .signedOut")
        sut.$state.dropFirst().sink { state in
            if state == .signedOut {
                expectation.fulfill()
            }
        }.store(in: &cancellables)

        mockFirebaseAuthClient.simulateAuthStateChange(to: nil)

        await fulfillment(of: [expectation], timeout: 1.0)
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertEqual(mockSecureStorage.clearUserIDCallCount, 1)
    }

    func testAuthStateListener_doesNotOverrideState_whenAuthenticating() async throws {
        sut.forceStateForTesting(.authenticating("Signing in..."))
        sut.isTestMode = false

        mockFirebaseAuthClient.simulateAuthStateChange(to: nil)
        try await Task.sleep(nanoseconds: 100_000_000)

        XCTAssertEqual(sut.state, .authenticating("Signing in..."))
    }

    // MARK: - Lifecycle Tests

    func testInit_addsStateDidChangeListener() {
        XCTAssertEqual(mockFirebaseAuthClient.addStateDidChangeListenerCallCount, 1)
    }

    func testInvalidate_removesStateDidChangeListener() {
        sut.invalidate()
        XCTAssertEqual(mockFirebaseAuthClient.removeStateDidChangeListenerCallCount, 1)
    }

    // MARK: - Email/Password Sign-In & Creation

    func testSignInWithEmail_Success_updatesStateToSignedIn() async throws {
        let expectedUser = createDummyAuthUser(uid: "emailUser1", providerID: "password")
        mockFirebaseAuthenticator.signInWithEmailResultProvider = { _, _ in .success(expectedUser) }

        await sut.signInWithEmail(email: "test@example.com", password: "password123")

        XCTAssertEqual(sut.state, .signedIn(expectedUser))
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 1)
        let lastUserID = await mockSecureStorage.getLastUserID()
        XCTAssertEqual(lastUserID, "emailUser1")
    }

    func testSignInWithEmail_Failure_WrongPassword_setsErrorAndRemainsSignedOut() async {
        let wrongPasswordError = AuthError.firebaseAuthError(FirebaseErrorData(code: AuthErrorCode.wrongPassword.rawValue, domain: AuthErrorDomain, message: ""))
        mockFirebaseAuthenticator.signInWithEmailResultProvider = { _, _ in .failure(wrongPasswordError) }

        await sut.signInWithEmail(email: "test@example.com", password: "wrongpassword")

        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertEqual(sut.lastError, wrongPasswordError)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 0)
    }

    func testCreateAccountWithEmail_Success_updatesStateToSignedIn() async throws {
        let newUser = createDummyAuthUser(uid: "newEmailUser", email: "new@example.com")
        mockFirebaseAuthenticator.createAccountWithEmailResultProvider = { _, _, _ in .success(newUser) }

        await sut.createAccountWithEmail(email: "new@example.com", password: "newPass123")

        XCTAssertEqual(sut.state, .signedIn(newUser))
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 1)
    }

    func testCreateAccountWithEmail_Failure_EmailAlreadyInUse_setsStateToEmailInUseSuggestSignIn() async throws {
        let existingEmail = "existing@example.com"
        let emailInUseError = AuthError.emailAlreadyInUseDuringCreation(email: existingEmail)
        mockFirebaseAuthenticator.createAccountWithEmailResultProvider = { _, _, _ in .failure(emailInUseError) }

        await sut.createAccountWithEmail(email: existingEmail, password: "anypassword")

        XCTAssertEqual(sut.state, .emailInUseSuggestSignIn(email: existingEmail))
        XCTAssertEqual(sut.lastError, emailInUseError)
        XCTAssertNil(sut.pendingCredentialToLinkAfterReauth)
    }

    // MARK: - Google & Apple Sign-In

    func testSignInWithGoogle_Success_updatesStateToSignedIn() async throws {
        let googleUser = createDummyAuthUser(uid: "googleUser1", providerID: "google.com")
        mockFirebaseAuthenticator.signInWithGoogleResultProvider = { _ in .success(googleUser) }

        await sut.signInWithGoogle(presentingViewController: dummyVC)

        XCTAssertEqual(sut.state, .signedIn(googleUser))
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 1)
    }

    func testSignInWithGoogle_Cancelled_setsErrorAndRemainsSignedOut() async {
        mockFirebaseAuthenticator.signInWithGoogleResultProvider = { _ in .failure(.cancelled) }

        await sut.signInWithGoogle(presentingViewController: dummyVC)

        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertEqual(sut.lastError, .cancelled)
    }

    func testSignInWithApple_Success_updatesStateToSignedIn() async throws {
        let appleUser = createDummyAuthUser(uid: "appleUser1", providerID: "apple.com")
        mockFirebaseAuthenticator.signInWithAppleResultProvider = { _, _ in .success(appleUser) }

        await sut.signInWithApple(presentingViewController: dummyVC)

        XCTAssertEqual(sut.state, .signedIn(appleUser))
        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockSecureStorage.saveUserIDCallCount, 1)
    }

    // MARK: - Sign Out

    func testSignOut_callsClientAndClearsData() async throws {
        sut.forceStateForTesting(.signedIn(createDummyAuthUser()))
        
        await sut.signOut()

        XCTAssertEqual(mockFirebaseAuthClient.signOutCallCount, 1)
        XCTAssertEqual(sut.state, .signedOut)
        XCTAssertEqual(mockSecureStorage.clearUserIDCallCount, 1) // This will now pass
        XCTAssertEqual(mockFirebaseAuthenticator.clearTemporaryCredentialsCallCount, 1) // This will now pass
        XCTAssertNil(sut.lastError)
    }

    // MARK: - Biometrics

    func testRequireBiometricAuthentication_WhenSignedOutAndAvailable_TransitionsState() {
        mockBiometricAuthenticator.mockIsAvailable = true
        sut.requireBiometricAuthentication()
        XCTAssertEqual(sut.state, .requiresBiometrics)
    }

    func testRequireBiometricAuthentication_WhenNotAvailable_DoesNotTransition() {
        mockBiometricAuthenticator.mockIsAvailable = false
        sut.requireBiometricAuthentication()
        XCTAssertEqual(sut.state, .signedOut)
    }

    func testRequireBiometricAuthentication_WhenSignedIn_DoesNotTransition() {
        sut.forceStateForTesting(.signedIn(createDummyAuthUser()))
        sut.requireBiometricAuthentication()
        XCTAssertTrue(sut.state.isSignedIn)
    }

    func testAuthenticateWithBiometrics_Success_updatesState() async throws {
        let firebaseUser = createDummyFirebaseUser(uid: "bioUser")
        mockFirebaseAuthClient.mockCurrentUser = firebaseUser
        sut.forceStateForTesting(.requiresBiometrics)
        mockBiometricAuthenticator.authResultProvider = { .success(()) }

        await sut.authenticateWithBiometrics(reason: "Test Bio")

        if case .signedIn(let signedInUser) = sut.state {
            XCTAssertEqual(signedInUser.uid, firebaseUser.uid)
        } else {
            XCTFail("Expected .signedIn state, got \(sut.state)")
        }
    }

    func testAuthenticateWithBiometrics_Failure_revertsToRequiresBiometrics() async {
        mockFirebaseAuthClient.mockCurrentUser = createDummyFirebaseUser()
        sut.forceStateForTesting(.requiresBiometrics)
        let bioError = AuthError.biometricsFailed(.userCancel)
        mockBiometricAuthenticator.authResultProvider = { .failure(bioError) }

        await sut.authenticateWithBiometrics(reason: "Test Bio")

        XCTAssertEqual(sut.state, .requiresBiometrics)
        XCTAssertEqual(sut.lastError, bioError)
    }

    // MARK: - Password Reset

    func testSendPasswordResetEmail_Success() async {
        await sut.sendPasswordResetEmail(to: "reset@example.com")

        XCTAssertNil(sut.lastError)
        XCTAssertEqual(mockFirebaseAuthenticator.sendPasswordResetEmailCallCount, 1)
        XCTAssertEqual(sut.state, .signedOut) // Reverts from .authenticating
    }

    func testSendPasswordResetEmail_Failure() async {
        let expectedError = AuthError.helpfulUserNotFound(email: "test@test.com")
        mockFirebaseAuthenticator.sendPasswordResetEmailError = expectedError

        await sut.sendPasswordResetEmail(to: "resetfail@example.com")

        XCTAssertEqual(sut.lastError, expectedError)
        XCTAssertEqual(mockFirebaseAuthenticator.sendPasswordResetEmailCallCount, 1)
    }

    // MARK: - Linking Flow

    func testLinkingFlow_SignInFailsWithAccountLinkingRequired_setsCorrectStateAndStoresCredential() async throws {
        let existingEmail = "linktest@example.com"
        let appleCredential = createPlaceholderAuthCredential(providerID: "apple.com")
        let linkingError = AuthError.accountLinkingRequired(email: existingEmail, attemptedProviderId: appleCredential.provider)

        mockFirebaseAuthenticator.signInWithAppleResultProvider = { _, _ in
            self.mockFirebaseAuthenticator.forcePendingCredentialForLinking(appleCredential)
            return .failure(linkingError)
        }

        await sut.signInWithApple(presentingViewController: dummyVC)

        guard case .requiresAccountLinking(let email, let providerId) = sut.state else {
            XCTFail("Expected .requiresAccountLinking state, got \(sut.state)")
            return
        }

        XCTAssertEqual(email, existingEmail)
        XCTAssertEqual(providerId, "apple.com")
        XCTAssertEqual(sut.lastError, linkingError)
        XCTAssertNotNil(sut.pendingCredentialToLinkAfterReauth)
        XCTAssertEqual(sut.pendingCredentialToLinkAfterReauth?.provider, "apple.com")
    }
}
