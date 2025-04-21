import Foundation
import Security

internal class KeychainStorage: SecureStorageProtocol {
    private let service = "com.yourappdomain.AuthKit" // Use a unique service name
    private let account = "lastUserID"

    func saveLastUserID(_ userID: String) throws {
        guard let data = userID.data(using: .utf8) else { return } // Or throw error
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        // Delete existing item first
        SecItemDelete(query as CFDictionary)

        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            // Throw a proper error
            print("Keychain save error: \(status)")
            throw AuthError.keychainError(status)
        }
         print("Keychain: Saved User ID \(userID)")
    }

    func getLastUserID() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)

        if status == errSecSuccess {
            guard let data = dataTypeRef as? Data,
                  let userID = String(data: data, encoding: .utf8) else {
                return nil
            }
            print("Keychain: Retrieved User ID \(userID)")
            return userID
        } else if status == errSecItemNotFound {
             print("Keychain: No User ID found")
            return nil
        } else {
            print("Keychain retrieve error: \(status)")
            // Handle or log other errors
            return nil
        }
    }

    func clearLastUserID() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
         print("Keychain: Cleared User ID")
        guard status == errSecSuccess || status == errSecItemNotFound else {
            // Throw a proper error
            print("Keychain clear error: \(status)")
            throw AuthError.keychainError(status)
        }
    }
}