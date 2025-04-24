import Foundation
import Security

// Assumed to be called only from @MainActor context in AuthService
internal class KeychainStorage: SecureStorageProtocol {
    private let service = "com.yourappdomain.AuthKit" // Use a unique service name
    private let account = "lastUserID"

    func saveLastUserID(_ userID: String) throws {
        guard let data = userID.data(using: .utf8) else {
            print("Keychain Error: Could not encode User ID")
            // Consider throwing a specific error
            throw AuthError.configurationError("Failed to encode User ID for Keychain.")
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly // Secure accessibility
        ]
        // Delete existing item first to ensure update works
        SecItemDelete(query as CFDictionary)
        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
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
            guard let data = dataTypeRef as? Data, let userID = String(data: data, encoding: .utf8) else {
                print("Keychain retrieve error: Failed to decode data.")
                return nil
            }
            print("Keychain: Retrieved User ID \(userID)")
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
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            print("Keychain clear error: \(status)")
            throw AuthError.keychainError(status)
        }
        print("Keychain: Cleared User ID (Status: \(status))")
    }
}
