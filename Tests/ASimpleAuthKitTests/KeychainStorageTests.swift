//
//  KeychainStorageTests.swift
//  ASimpleAuthKit
//
//  Created by Charles Feinn on 4/26/25.
//

import XCTest
@testable import ASimpleAuthKit

// These tests interact with the actual keychain.
// Ensure Keychain Sharing entitlement is NOT enabled for the test target
// unless you are specifically testing sharing scenarios.
@MainActor
class KeychainStorageTests: XCTestCase {

    var sut: KeychainStorage!
    // Use a unique service name for tests to avoid interfering with the real app
    let testServiceSuffix = ".tests"
    var testServiceNameIsolated: String! // For non-shared tests
    var testServiceNameShared: String! // For shared tests (constant)
    var testAccessGroup: String? = "com.yourcompany.ASimpleAuthKitTests.SharedGroup" // Example - MUST MATCH ENTITLEMENTS

    override func setUp() async throws {
        // Call super first (generally safer before async operations)
        try super.setUpWithError()

        // Explicitly run the rest of the setup on the MainActor
        try await MainActor.run { // Use try await
            guard let bundleId = Bundle(for: type(of: self)).bundleIdentifier else {
                throw TestError.testSetupFailed("Test bundle identifier not found")
            }
            // Accessing/mutating self's properties is safe inside MainActor.run
            self.testServiceNameIsolated = bundleId
            self.testServiceNameShared = "io.appsimple.ASimpleAuthKit.SharedAuth"

            // Clean up potential leftovers before each test
            // Creating/using KeychainStorage (also @MainActor) is safe here
            let isolatedStorage = KeychainStorage(service: self.testServiceNameIsolated, accessGroup: nil)
            try? isolatedStorage.clearLastUserID()

            if let group = self.testAccessGroup {
                let sharedStorage = KeychainStorage(service: self.testServiceNameShared, accessGroup: group)
                try? sharedStorage.clearLastUserID()
            }
        }
    }

    // Use tearDown() async throws for async cleanup that can throw
    override func tearDown() async throws {
        // Explicitly run cleanup on the MainActor
        await MainActor.run {
            // Accessing self's properties (like testServiceNameIsolated) is safe here
            // because the class is @MainActor and we're inside MainActor.run

            let isolatedStorage = KeychainStorage(service: self.testServiceNameIsolated, accessGroup: nil)
            // Using try? for cleanup is often acceptable, as failure might not invalidate subsequent tests
            try? isolatedStorage.clearLastUserID()

            // Accessing self.testAccessGroup is safe
            if let group = self.testAccessGroup {
                let sharedStorage = KeychainStorage(service: self.testServiceNameShared, accessGroup: group)
                try? sharedStorage.clearLastUserID()
            }
            // Setting instance variable to nil is safe
            self.sut = nil
        }
    }

    // MARK: - Isolated Storage Tests (No Access Group)

    func testSaveAndGetLastUserID_Isolated_Success() throws {
        // Arrange
        sut = KeychainStorage(service: testServiceNameIsolated, accessGroup: nil) // Use isolated service
        let userID = "testUser123"

        // Act
        try sut.saveLastUserID(userID)
        let retrievedID = sut.getLastUserID()

        // Assert
        XCTAssertEqual(retrievedID, userID)
    }

    func testGetLastUserID_Isolated_WhenNoUserSaved_ReturnsNil() {
        // Arrange
        sut = KeychainStorage(service: testServiceNameIsolated, accessGroup: nil)
        // (already cleared in setup)

        // Act
        let retrievedID = sut.getLastUserID()

        // Assert
        XCTAssertNil(retrievedID)
    }

    func testClearLastUserID_Isolated_RemovesSavedUser() throws {
        // Arrange
        sut = KeychainStorage(service: testServiceNameIsolated, accessGroup: nil)
        let userID = "userToClear"
        try sut.saveLastUserID(userID)
        XCTAssertNotNil(sut.getLastUserID(), "User ID should be present before clearing")

        // Act
        try sut.clearLastUserID()
        let retrievedID = sut.getLastUserID()

        // Assert
        XCTAssertNil(retrievedID, "User ID should be nil after clearing")
    }

    func testSaveLastUserID_Isolated_OverwritesExistingUser() throws {
        // Arrange
        sut = KeychainStorage(service: testServiceNameIsolated, accessGroup: nil)
        let initialUserID = "initialUser"
        let newUserID = "newUser"
        try sut.saveLastUserID(initialUserID)

        // Act
        try sut.saveLastUserID(newUserID)
        let retrievedID = sut.getLastUserID()

        // Assert
        XCTAssertEqual(retrievedID, newUserID)
    }

    // MARK: - Shared Storage Tests (With Access Group)
    // IMPORTANT: These tests require the test target to have Keychain Sharing enabled
    // with the identifier matching `testAccessGroup`. Skip if not configured.

    func testSaveAndGetLastUserID_Shared_Success() throws {
        guard testAccessGroup != nil else { throw XCTSkip("Keychain Access Group not configured for tests") }
        // Arrange
        sut = KeychainStorage(service: testServiceNameShared, accessGroup: testAccessGroup) // Use shared service & group
        let userID = "sharedUser456"

        // Act
        try sut.saveLastUserID(userID)
        let retrievedID = sut.getLastUserID()

        // Assert
        XCTAssertEqual(retrievedID, userID)
    }

    func testGetLastUserID_Shared_WhenNoUserSaved_ReturnsNil() throws {
        guard testAccessGroup != nil else { throw XCTSkip("Keychain Access Group not configured for tests") }
        // Arrange
        sut = KeychainStorage(service: testServiceNameShared, accessGroup: testAccessGroup)
        // (already cleared in setup)

        // Act
        let retrievedID = sut.getLastUserID()

        // Assert
        XCTAssertNil(retrievedID)
    }

    func testClearLastUserID_Shared_RemovesSavedUser() throws {
        guard testAccessGroup != nil else { throw XCTSkip("Keychain Access Group not configured for tests") }
        // Arrange
        sut = KeychainStorage(service: testServiceNameShared, accessGroup: testAccessGroup)
        let userID = "sharedUserToClear"
        try sut.saveLastUserID(userID)
        XCTAssertNotNil(sut.getLastUserID(), "Shared User ID should be present before clearing")

        // Act
        try sut.clearLastUserID()
        let retrievedID = sut.getLastUserID()

        // Assert
        XCTAssertNil(retrievedID, "Shared User ID should be nil after clearing")
    }

    func testSaveLastUserID_Shared_OverwritesExistingUser() throws {
        guard testAccessGroup != nil else { throw XCTSkip("Keychain Access Group not configured for tests") }
        // Arrange
        sut = KeychainStorage(service: testServiceNameShared, accessGroup: testAccessGroup)
        let initialUserID = "initialSharedUser"
        let newUserID = "newSharedUser"
        try sut.saveLastUserID(initialUserID)

        // Act
        try sut.saveLastUserID(newUserID)
        let retrievedID = sut.getLastUserID()

        // Assert
        XCTAssertEqual(retrievedID, newUserID)
    }

    // Test isolation between shared and non-shared storage
    func testStorageIsolation_SharedDoesNotAffectIsolated() throws {
        guard testAccessGroup != nil else { throw XCTSkip("Keychain Access Group not configured for tests") }
        // Arrange
        let isolatedSUT = KeychainStorage(service: testServiceNameIsolated, accessGroup: nil)
        let sharedSUT = KeychainStorage(service: testServiceNameShared, accessGroup: testAccessGroup)
        let isolatedUser = "isolatedOnly"
        let sharedUser = "sharedOnly"

        // Act
        try isolatedSUT.saveLastUserID(isolatedUser)
        try sharedSUT.saveLastUserID(sharedUser)

        // Assert
        XCTAssertEqual(isolatedSUT.getLastUserID(), isolatedUser, "Isolated storage should hold isolated user")
        XCTAssertEqual(sharedSUT.getLastUserID(), sharedUser, "Shared storage should hold shared user")

        // Clear shared, check isolated is unaffected
        try sharedSUT.clearLastUserID()
        XCTAssertEqual(isolatedSUT.getLastUserID(), isolatedUser, "Isolated storage should remain after clearing shared")
        XCTAssertNil(sharedSUT.getLastUserID(), "Shared storage should be clear")
    }
}
