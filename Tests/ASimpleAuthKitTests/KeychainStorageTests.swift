import XCTest
@testable import ASimpleAuthKit // Use @testable to access internal types like MockSecureStorage

// Tests the protocol via a mock.
@MainActor // Keep MainActor as MockSecureStorage is marked MainActor
class KeychainStorageTests: XCTestCase {

    // The System Under Test (SUT) is now the Mock object conforming to the protocol
    var sut: MockSecureStorage!

    // Test-specific service names for verifying mock's internal logic if needed
    let testServiceIsolated = Bundle(for: KeychainStorageTests.self).bundleIdentifier ?? "com.example.DefaultTestBundleID.tests" // More robust way to get test bundle ID
    let testServiceShared = "io.appsimple.ASimpleAuthKit.SharedAuth" // Matches mock/real shared constant
    let testAccessGroup = "io.appsimple.ASimpleAuthKitTests.SharedGroup" // Example group identifier

    override func setUp() async throws { // Keep setUp synchronous
        sut = MockSecureStorage(service: nil, accessGroup: nil) // Use default init (isolated)
        sut.reset() // Ensure the mock is clean before every test
    }

    override func tearDown() async throws { // Keep tearDown synchronous
        sut = nil
    }

    // MARK: - Protocol Compliance Tests (Using Mock)

    func testSaveLastUserID_Success() async throws {
        // Arrange
        let userID = "testUser123"
        XCTAssertEqual(sut.saveUserIDCallCount, 0, "Precondition: Save count should be 0")
        
        let preSaveID = await sut.getLastUserID()
        XCTAssertNil(preSaveID, "Precondition: Storage should be empty for this key")
        sut.getLastUserIDCallCount = 0 // Reset after precondition check

        // Act
        try await sut.saveLastUserID(userID)

        // Assert
        XCTAssertEqual(sut.saveUserIDCallCount, 1, "Save should be called once")
        XCTAssertEqual(sut.lastSavedUserID, userID, "Mock should have recorded the saved user ID")
        XCTAssertEqual(sut.storage["\(sut.service)-lastUserID"], userID, "Mock's internal storage should contain the ID for the correct key")
    }

    func testGetLastUserID_WhenNoUserSaved_ReturnsNil() async {
        // Arrange
        XCTAssertEqual(sut.getLastUserIDCallCount, 0, "Precondition: Get count should be 0")
        XCTAssertTrue(sut.storage.isEmpty, "Precondition: Mock storage should be empty")

        // Act
        let retrievedID = await sut.getLastUserID() // await is correct here

        // Assert
        XCTAssertNil(retrievedID, "Should return nil when no user ID is saved") // XCTAssertNil handles the result directly
        XCTAssertEqual(sut.getLastUserIDCallCount, 1, "Get should be called once")
    }

    func testGetLastUserID_WhenUserSaved_ReturnsUserID() async throws {
        // Arrange
        let userID = "existingUser456"
        try await sut.saveLastUserID(userID)
        sut.getLastUserIDCallCount = 0

        // Act
        let retrievedID = await sut.getLastUserID() // await is correct here

        // Assert
        XCTAssertEqual(retrievedID, userID, "Should return the previously saved user ID") // XCTAssertEqual handles the result directly
        XCTAssertEqual(sut.getLastUserIDCallCount, 1, "Get should be called once")
    }

    func testClearLastUserID_RemovesSavedUser() async throws {
        // Arrange
        let userID = "userToClear"
        try await sut.saveLastUserID(userID)
        
        let preClearID = await sut.getLastUserID()
        XCTAssertNotNil(preClearID, "Precondition: User ID should be present before clearing")
        XCTAssertEqual(sut.clearUserIDCallCount, 0, "Precondition: Clear count should be 0")
        sut.getLastUserIDCallCount = 0

        // Act
        try await sut.clearLastUserID()

        // Assert
        let postClearID = await sut.getLastUserID()
        XCTAssertNil(postClearID, "User ID should be nil after clearing")
        XCTAssertEqual(sut.clearUserIDCallCount, 1, "Clear should be called once")
        XCTAssertEqual(sut.getLastUserIDCallCount, 1, "Get should have been called (in assertion)")
        XCTAssertNil(sut.storage["\(sut.service)-lastUserID"], "Mock's internal storage should be empty for this key")
    }

    func testSaveLastUserID_OverwritesExistingUser() async throws {
        // Arrange
        let initialUserID = "initialUser"
        let newUserID = "newUser"
        try await sut.saveLastUserID(initialUserID)
        // <<< FIXED: Await before assert >>>
        let preOverwriteID = await sut.getLastUserID()
        XCTAssertEqual(preOverwriteID, initialUserID, "Precondition: Initial user should be saved")
        sut.saveUserIDCallCount = 0
        sut.getLastUserIDCallCount = 0

        // Act
        try await sut.saveLastUserID(newUserID)

        // Assert
        let postOverwriteID = await sut.getLastUserID()
        XCTAssertEqual(postOverwriteID, newUserID, "The new user ID should overwrite the old one")
        XCTAssertEqual(sut.saveUserIDCallCount, 1, "Save should be called once (for the overwrite)")
        XCTAssertEqual(sut.lastSavedUserID, newUserID, "Mock should record the latest saved ID")
        XCTAssertEqual(sut.storage["\(sut.service)-lastUserID"], newUserID, "Mock storage should hold the new user ID")
    }

    // MARK: - Mock Behavior Tests (Simulating Shared vs. Isolated)

    func testMockInitialization_Isolated() { // Sync test
        sut = MockSecureStorage(service: nil, accessGroup: nil)
        let expectedService = Bundle(for: MockSecureStorage.self).bundleIdentifier ?? "com.example.DefaultTestBundleID"
        XCTAssertEqual(sut.service, expectedService, "Mock service should default to bundle ID when no group is provided")
        XCTAssertNil(sut.accessGroup, "Mock access group should be nil")
    }

    func testMockInitialization_Shared() { // Sync test
        sut = MockSecureStorage(service: nil, accessGroup: testAccessGroup)
        XCTAssertEqual(sut.service, testServiceShared, "Mock service should use the shared constant when a group is provided")
        XCTAssertEqual(sut.accessGroup, testAccessGroup, "Mock access group should match the provided group")
    }

    func testMockStorageIsolation_SharedDoesNotAffectIsolated() async throws {
        // Arrange
        let isolatedSUT = MockSecureStorage(service: nil, accessGroup: nil)
        let sharedSUT = MockSecureStorage(service: nil, accessGroup: testAccessGroup)
        let isolatedUser = "isolatedOnly"
        let sharedUser = "sharedOnly"
        XCTAssertNotEqual(isolatedSUT.service, sharedSUT.service)

        // Act
        try await isolatedSUT.saveLastUserID(isolatedUser)
        try await sharedSUT.saveLastUserID(sharedUser)

        // Assert
        let isolatedUserActual1 = await isolatedSUT.getLastUserID()
        XCTAssertEqual(isolatedUserActual1, isolatedUser, "Isolated mock should hold the isolated user")
        XCTAssertNil(isolatedSUT.storage["\(sharedSUT.service)-lastUserID"], "Isolated mock storage should not contain the shared key")

        let sharedUserActual1 = await sharedSUT.getLastUserID()
        XCTAssertEqual(sharedUserActual1, sharedUser, "Shared mock should hold the shared user")
        XCTAssertNil(sharedSUT.storage["\(isolatedSUT.service)-lastUserID"], "Shared mock storage should not contain the isolated key")

        // Act
        try await sharedSUT.clearLastUserID()

        // Assert
        let isolatedUserActual2 = await isolatedSUT.getLastUserID()
        XCTAssertEqual(isolatedUserActual2, isolatedUser, "Isolated mock should remain unaffected after clearing shared mock")

        let sharedUserActual2 = await sharedSUT.getLastUserID()
        XCTAssertNil(sharedUserActual2, "Shared mock should be clear")
        XCTAssertNil(sharedSUT.storage["\(sharedSUT.service)-lastUserID"], "Shared mock storage should be empty for its key")
    }

    // MARK: - Error Handling Tests (Using Mock's Error Simulation)

    func testSaveLastUserID_ThrowsError() async {
        // Arrange
        let expectedError = AuthError.keychainError(errSecInteractionNotAllowed)
        sut.saveError = expectedError
        let userID = "userThatWillFail"

        // Act & Assert using do-catch
        do {
            try await sut.saveLastUserID(userID) // Attempt the throwing async call
            XCTFail("Expected saveLastUserID to throw an error, but it did not.") // Fail if it *doesn't* throw
        } catch {
            // Assert on the caught error
            guard let authError = error as? AuthError else {
                XCTFail("Caught error is not the expected AuthError type: \(error)")
                return
            }
            XCTAssertEqual(authError, expectedError, "The caught error should match the expected AuthError")
        }

        // Verify mock state (remains the same)
        XCTAssertEqual(sut.saveUserIDCallCount, 0)
        let storageValue = await sut.getLastUserID()
        XCTAssertNil(storageValue)
    }

    func testClearLastUserID_ThrowsError() async throws { // Keep throws for arrange step
        // Arrange
        let expectedError = AuthError.keychainError(errSecAuthFailed)
        sut.clearError = expectedError
        try await sut.saveLastUserID("someUser") // Arrange still needs await

        // Act & Assert using do-catch
        do {
            try await sut.clearLastUserID() // Attempt the throwing async call
            XCTFail("Expected clearLastUserID to throw an error, but it did not.") // Fail if it *doesn't* throw
        } catch {
            // Assert on the caught error
            guard let authError = error as? AuthError else {
                XCTFail("Caught error is not the expected AuthError type: \(error)")
                return
            }
            XCTAssertEqual(authError, expectedError, "The caught error should match the expected AuthError")
        }

        // Verify state (remains the same)
        XCTAssertEqual(sut.clearUserIDCallCount, 0)
        let userIDAfterFailedClear = await sut.getLastUserID()
        XCTAssertNotNil(userIDAfterFailedClear, "User ID should still exist if clear failed")
    }
}
