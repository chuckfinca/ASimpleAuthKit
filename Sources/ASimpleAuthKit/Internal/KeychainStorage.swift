import Foundation
import Security

// Called only from @MainActor context in AuthService,
// but performs keychain operations on a background thread via Task.detached.
internal class KeychainStorage: SecureStorageProtocol {

    private let service: String
    private let account = "lastUserID"
    private let accessGroup: String?

    internal init(service: String? = nil, accessGroup: String? = nil) {
        self.accessGroup = accessGroup

        // Determine the service name (same logic)
        if let explicitService = service {
            self.service = explicitService
        } else if accessGroup != nil {
            self.service = "io.appsimple.ASimpleAuthKit.SharedAuth"
        } else {
            guard let bundleIdentifier = Bundle.main.bundleIdentifier else {
                fatalError("ASimpleAuthKit Keychain Error: Could not retrieve bundle identifier. Ensure CFBundleIdentifier is set in the app's Info.plist.")
            }
            self.service = bundleIdentifier
        }
        print("KeychainStorage initialized with service: '\(self.service)' \(self.accessGroup != nil ? "and access group: '\(self.accessGroup!)'" : "(no access group)")")
    }

    convenience init(accessGroup: String? = nil) {
        self.init(service: nil, accessGroup: accessGroup)
    }

    private func createBaseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        return query
    }

    func saveLastUserID(_ userID: String) async throws {
        print("Keychain: Initiating async save for User ID \(userID)...")
        
        // Perform actual keychain operation in detached task to avoid blocking caller
        try await Task.detached { [service, account, accessGroup] in
            // Recreate base query inside task if needed, or capture necessary properties
            var baseQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account
            ]
            if let group = accessGroup {
                baseQuery[kSecAttrAccessGroup as String] = group
            }

            guard let data = userID.data(using: .utf8) else {
                print("Keychain Task Error: Could not encode User ID")
                throw AuthError.configurationError("Failed to encode User ID for Keychain.")
            }

            var writeQuery = baseQuery
            writeQuery[kSecValueData as String] = data
            writeQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

            // Delete existing item first (synchronously within task)
            let deleteStatus = SecItemDelete(baseQuery as CFDictionary)
            // Ignore "not found" error during delete, but log others
            if deleteStatus != errSecSuccess && deleteStatus != errSecItemNotFound {
                 print("Keychain Task Warning: Error deleting existing item before save (Status: \(deleteStatus)). Proceeding with add attempt.")
             }

            // Add new item (synchronously within task)
            let addStatus = SecItemAdd(writeQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                print("Keychain Task Error: Save failed (Status: \(addStatus))")
                throw AuthError.keychainError(addStatus)
            }
            // This print happens on the detached task's thread
            print("Keychain Task: Successfully saved User ID \(userID) to service '\(service)' \(accessGroup != nil ? "in group \(accessGroup!)" : "")")

        }.value // Propagates error thrown from the detached task
        
        // This print happens back on the calling actor's thread (MainActor)
        print("Keychain: Async save completed for User ID \(userID)")
    }

    func getLastUserID() async -> String? {
        print("Keychain: Initiating async retrieval of User ID...")
        // Perform actual keychain operation in detached task
        let userID = await Task.detached { [service, account, accessGroup] () -> String? in
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecReturnData as String: kCFBooleanTrue!,
                kSecMatchLimit as String: kSecMatchLimitOne
            ]
            if let group = accessGroup {
                query[kSecAttrAccessGroup as String] = group
            }

            var dataTypeRef: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)

            if status == errSecSuccess {
                guard let data = dataTypeRef as? Data, let retrievedUserID = String(data: data, encoding: .utf8) else {
                    print("Keychain Task Error: Failed to decode retrieved data.")
                    return nil // Failed to decode
                }
                 print("Keychain Task: Retrieved User ID \(retrievedUserID) from service '\(service)' \(accessGroup != nil ? "in group \(accessGroup!)" : "")")
                return retrievedUserID
                
            } else if status == errSecItemNotFound {
                print("Keychain Task: No User ID found (Status: \(status))")
                return nil // Not found is expected
                
            } else {
                print("Keychain Task Error: Retrieval failed (Status: \(status))")
                return nil // Other error occurred
            }
        }.value
        // This print happens back on the calling actor's thread (MainActor)
        print("Keychain: Async retrieval completed. Found User ID: \(userID ?? "nil")")
        return userID
    }

    func clearLastUserID() async throws {
         print("Keychain: Initiating async clear of User ID...")
        // Perform actual keychain operation in detached task
        try await Task.detached { [service, account, accessGroup] in
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account
            ]
            if let group = accessGroup {
                query[kSecAttrAccessGroup as String] = group
            }

            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                 print("Keychain Task Error: Clear failed (Status: \(status))")
                throw AuthError.keychainError(status)
            }
             print("Keychain Task: Cleared User ID from service '\(service)' \(accessGroup != nil ? "in group \(accessGroup!)" : "") (Status: \(status))")
        }.value // Propagates error
        
        // This print happens back on the calling actor's thread (MainActor)
        print("Keychain: Async clear completed.")
    }
}
