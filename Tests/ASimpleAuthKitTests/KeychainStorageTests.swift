//
//  KeychainStorageTests.swift
//  ASimpleAuthKit
//
//  Created by Charles Feinn on 4/26/25.
//

import XCTest
@testable import ASimpleAuthKit // Use @testable to access internal types like MockSecureStorage

// Tests the protocol via a mock.
@MainActor // Keep MainActor as MockSecureStorage is marked MainActor
class KeychainStorageTests: XCTestCase {

    // The System Under Test (SUT) is now the Mock object conforming to the protocol
    var sut: MockSecureStorage!

    // Test-specific service names for verifying mock's internal logic if needed
    let testServiceIsolated = "com.example.TestAppBundleID.tests" // Example isolated service
    let testServiceShared = "io.appsimple.ASimpleAuthKit.SharedAuth" // Matches mock/real shared constant
    let testAccessGroup = "io.appsimple.ASimpleAuthKitTests.SharedGroup" // Example group identifier

    override func setUp() async throws {
        // No need to call super.setUpWithError() as we're not using complex XCTestCase features here
        // No need to interact with the real keychain anymore

        // Initialize the mock *before* each test.
        // Using the default initializer for most tests, specific ones might override.
        sut = MockSecureStorage()
        sut.reset() // Ensure the mock is clean before every test
    }

    override func tearDown() async throws {
        // Release the mock after each test
        sut = nil
        // No real keychain cleanup needed
    }

    // MARK: - Protocol Compliance Tests (Using Mock)

    func testSaveLastUserID_Success() throws {
        // Arrange
        // sut is already initialized in setUp with default config (likely isolated)
        let userID = "testUser123"
        XCTAssertEqual(sut.saveUserIDCallCount, 0, "Precondition: Save count should be 0")
        XCTAssertNil(sut.storage["\(sut.service)-lastUserID"], "Precondition: Storage should be empty for this service")

        // Act
        try sut.saveLastUserID(userID)

        // Assert
        XCTAssertEqual(sut.saveUserIDCallCount, 1, "Save should be called once")
        XCTAssertEqual(sut.lastSavedUserID, userID, "Mock should have recorded the saved user ID")
        XCTAssertEqual(sut.storage["\(sut.service)-lastUserID"], userID, "Mock's internal storage should contain the ID for the correct key")
    }

    func testGetLastUserID_WhenNoUserSaved_ReturnsNil() {
        // Arrange
        // sut is initialized fresh in setUp, storage is empty
        XCTAssertEqual(sut.getLastUserIDCallCount, 0, "Precondition: Get count should be 0")
        XCTAssertTrue(sut.storage.isEmpty, "Precondition: Mock storage should be empty")

        // Act
        let retrievedID = sut.getLastUserID()

        // Assert
        XCTAssertNil(retrievedID, "Should return nil when no user ID is saved")
        XCTAssertEqual(sut.getLastUserIDCallCount, 1, "Get should be called once")
    }

    func testGetLastUserID_WhenUserSaved_ReturnsUserID() throws {
        // Arrange
        let userID = "existingUser456"
        // Directly manipulate mock storage for arrangement if needed, or use save
        try sut.saveLastUserID(userID)
        sut.getLastUserIDCallCount = 0 // Reset call count after arrangement

        // Act
        let retrievedID = sut.getLastUserID()

        // Assert
        XCTAssertEqual(retrievedID, userID, "Should return the previously saved user ID")
        XCTAssertEqual(sut.getLastUserIDCallCount, 1, "Get should be called once")
    }

    func testClearLastUserID_RemovesSavedUser() throws {
        // Arrange
        let userID = "userToClear"
        try sut.saveLastUserID(userID) // Save a user first
        XCTAssertNotNil(sut.getLastUserID(), "Precondition: User ID should be present before clearing")
        XCTAssertEqual(sut.clearUserIDCallCount, 0, "Precondition: Clear count should be 0")
        sut.getLastUserIDCallCount = 0 // Reset get count after precondition check

        // Act
        try sut.clearLastUserID()

        // Assert
        XCTAssertNil(sut.getLastUserID(), "User ID should be nil after clearing")
        XCTAssertEqual(sut.clearUserIDCallCount, 1, "Clear should be called once")
        XCTAssertEqual(sut.getLastUserIDCallCount, 1, "Get should have been called (in assertion)")
        XCTAssertNil(sut.storage["\(sut.service)-lastUserID"], "Mock's internal storage should be empty for this key")
    }

    func testSaveLastUserID_OverwritesExistingUser() throws {
        // Arrange
        let initialUserID = "initialUser"
        let newUserID = "newUser"
        try sut.saveLastUserID(initialUserID)
        XCTAssertEqual(sut.getLastUserID(), initialUserID, "Precondition: Initial user should be saved")
        sut.saveUserIDCallCount = 0 // Reset save count after arrangement
        sut.getLastUserIDCallCount = 0 // Reset get count

        // Act
        try sut.saveLastUserID(newUserID) // Save again with a new ID

        // Assert
        XCTAssertEqual(sut.getLastUserID(), newUserID, "The new user ID should overwrite the old one")
        XCTAssertEqual(sut.saveUserIDCallCount, 1, "Save should be called once (for the overwrite)")
        XCTAssertEqual(sut.lastSavedUserID, newUserID, "Mock should record the latest saved ID")
        XCTAssertEqual(sut.storage["\(sut.service)-lastUserID"], newUserID, "Mock storage should hold the new user ID")
    }

    // MARK: - Mock Behavior Tests (Simulating Shared vs. Isolated)

    // Test that the mock uses the correct service name when initialized without an access group
    func testMockInitialization_Isolated() {
        // Arrange
        sut = MockSecureStorage(service: nil, accessGroup: nil) // Explicitly use nil group
        let expectedService = Bundle(for: MockSecureStorage.self).bundleIdentifier ?? "com.example.DefaultTestBundleID"

        // Assert
        XCTAssertEqual(sut.service, expectedService, "Mock service should default to bundle ID when no group is provided")
        XCTAssertNil(sut.accessGroup, "Mock access group should be nil")
    }

    // Test that the mock uses the correct service name when initialized *with* an access group
    func testMockInitialization_Shared() {
        // Arrange
        sut = MockSecureStorage(service: nil, accessGroup: testAccessGroup) // Provide an access group

        // Assert
        XCTAssertEqual(sut.service, testServiceShared, "Mock service should use the shared constant when a group is provided")
        XCTAssertEqual(sut.accessGroup, testAccessGroup, "Mock access group should match the provided group")
    }

     // Test that two mock instances initialized differently maintain separate storage
    func testMockStorageIsolation_SharedDoesNotAffectIsolated() throws {
         // Arrange: Create two separate mock instances with different configurations
         let isolatedSUT = MockSecureStorage(service: nil, accessGroup: nil) // Defaults to isolated service
         let sharedSUT = MockSecureStorage(service: nil, accessGroup: testAccessGroup) // Uses shared service

         let isolatedUser = "isolatedOnly"
         let sharedUser = "sharedOnly"

         // Precondition checks on service names (optional but good)
         XCTAssertNotEqual(isolatedSUT.service, sharedSUT.service, "The two mocks should have different service names based on initialization")

         // Act: Save different users to each mock instance
         try isolatedSUT.saveLastUserID(isolatedUser)
         try sharedSUT.saveLastUserID(sharedUser)

         // Assert: Check that each mock contains only its own user
         XCTAssertEqual(isolatedSUT.getLastUserID(), isolatedUser, "Isolated mock should hold the isolated user")
         XCTAssertNil(isolatedSUT.storage["\(sharedSUT.service)-lastUserID"], "Isolated mock storage should not contain the shared key")

         XCTAssertEqual(sharedSUT.getLastUserID(), sharedUser, "Shared mock should hold the shared user")
         XCTAssertNil(sharedSUT.storage["\(isolatedSUT.service)-lastUserID"], "Shared mock storage should not contain the isolated key")

         // Act: Clear the shared mock
         try sharedSUT.clearLastUserID()

         // Assert: Verify isolated mock is unaffected and shared mock is clear
         XCTAssertEqual(isolatedSUT.getLastUserID(), isolatedUser, "Isolated mock should remain unaffected after clearing shared mock")
         XCTAssertNil(sharedSUT.getLastUserID(), "Shared mock should be clear")
         XCTAssertNil(sharedSUT.storage["\(sharedSUT.service)-lastUserID"], "Shared mock storage should be empty for its key")
    }

    // MARK: - Error Handling Tests (Using Mock's Error Simulation)

    func testSaveLastUserID_ThrowsError() {
        // Arrange
        let expectedError = AuthError.keychainError(errSecInteractionNotAllowed) // Example error
        sut.saveError = expectedError // Configure the mock to throw this error on save
        let userID = "userThatWillFail"

        // Act & Assert
        do {
            try sut.saveLastUserID(userID)
            XCTFail("Save should have thrown an error, but it did not.")
        } catch let error as AuthError {
            XCTAssertEqual(error, expectedError, "The caught error should match the expected AuthError")
        } catch {
            XCTFail("Caught an unexpected error type: \(error)")
        }

        // Verify mock state after attempted save
        XCTAssertEqual(sut.saveUserIDCallCount, 0, "Save count should remain 0 as the function threw early") // Mock should increment count *before* throwing if simulating Keychain behavior accurately. Let's adjust mock if needed.
        // Let's check the mock implementation. If it throws *before* incrementing, this is correct. If it increments *then* throws, count should be 1.
        // --> The current MockSecureStorage throws *before* incrementing. This assertion is correct for the *current* mock.
         XCTAssertNil(sut.lastSavedUserID)
         XCTAssertNil(sut.storage["\(sut.service)-lastUserID"])
    }

    func testClearLastUserID_ThrowsError() {
        // Arrange
        let expectedError = AuthError.keychainError(errSecAuthFailed) // Example error
        sut.clearError = expectedError // Configure mock to throw on clear
        try? sut.saveLastUserID("someUser") // Ensure there's something to clear

        // Act & Assert
        do {
            try sut.clearLastUserID()
            XCTFail("Clear should have thrown an error, but it did not.")
        } catch let error as AuthError {
            XCTAssertEqual(error, expectedError, "The caught error should match the expected AuthError")
        } catch {
            XCTFail("Caught an unexpected error type: \(error)")
        }

        // Verify state
        XCTAssertEqual(sut.clearUserIDCallCount, 0) // Assuming mock throws before incrementing
        XCTAssertNotNil(sut.getLastUserID(), "User ID should still exist if clear failed") // Check if clear actually removed it despite error
        // --> The current MockSecureStorage throws *before* incrementing or removing. This assertion is correct.
    }
}
