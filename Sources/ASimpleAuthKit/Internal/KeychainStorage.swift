import Foundation
import Security

// Assumed to be called only from @MainActor context in AuthService
internal class KeychainStorage: SecureStorageProtocol {

    private let service: String
    private let account = "lastUserID"
    private let accessGroup: String?

    init(accessGroup: String? = nil) {
        self.accessGroup = accessGroup

        guard let bundleIdentifier = Bundle.main.bundleIdentifier else {
            fatalError("ASimpleAuthKit Error: Could not retrieve bundle identifier. Ensure CFBundleIdentifier is set in the app's Info.plist.")
        }
        self.service = self.accessGroup != nil ? "io.appsimple.ASimpleAuthKit" : bundleIdentifier
        print("KeychainStorage initialized with service: \(self.service)")
    }

    private func createBaseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, // Use the determined service name
            kSecAttrAccount as String: account
        ]
        // Conditionally add the access group
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        return query
    }

    func saveLastUserID(_ userID: String) throws {
        guard let data = userID.data(using: .utf8) else {
            print("Keychain Error: Could not encode User ID")
            // Consider throwing a specific error
            throw AuthError.configurationError("Failed to encode User ID for Keychain.")
        }

        var query = createBaseQuery() // Start with base query
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly // Or a shareable option like kSecAttrAccessibleAfterFirstUnlock

        // Delete existing item first (using the same base query)
        SecItemDelete(createBaseQuery() as CFDictionary)

        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            print("Keychain save error: \(status)")
            throw AuthError.keychainError(status)
        }
        print("Keychain: Saved User ID \(userID) to service '\(service)' \(accessGroup != nil ? "in group \(accessGroup!)" : "")")
    }

    func getLastUserID() -> String? {
        var query = createBaseQuery()
        query[kSecReturnData as String] = kCFBooleanTrue!
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        
        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)

        if status == errSecSuccess {
            guard let data = dataTypeRef as? Data, let userID = String(data: data, encoding: .utf8) else {
                print("Keychain retrieve error: Failed to decode data.")
                return nil
            }
            print("Keychain: Retrieved User ID \(userID) from service '\(service)' \(accessGroup != nil ? "in group \(accessGroup!)" : "")")
            return userID
        } else if status == errSecItemNotFound {
            print("Keychain: No User ID found")
            return nil
        } else {
            print("Keychain retrieve error: \(status)")
            // Consider logging this error but returning nil
            return nil
        }
    }

    func clearLastUserID() throws {
        let query = createBaseQuery()
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            print("Keychain clear error: \(status)")
            throw AuthError.keychainError(status)
        }
        print("Keychain: Cleared User ID from service '\(service)' \(accessGroup != nil ? "in group \(accessGroup!)" : "") (Status: \(status))")
    }
}
