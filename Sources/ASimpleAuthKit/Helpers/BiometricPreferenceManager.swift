import Foundation
import Security

@MainActor
public class BiometricPreferenceManager {

    // MARK: - Singleton
    public static let shared = BiometricPreferenceManager(keychainAccessGroup: nil)

    // MARK: - Private Properties
    private let service: String
    private let keychainAccessGroup: String?

    // Keychain keys
    private enum KeychainKey {
        static let biometricEnabled = "biometric_enabled"
        static let lastAuthenticatedUserID = "biometric_last_user_id"
    }

    // MARK: - Initialization

    // Designated initializer
    internal init(keychainAccessGroup: String?) {
        self.keychainAccessGroup = keychainAccessGroup

        // Determine the service name. For BiometricPreferenceManager, the service name
        // was originally derived solely from the bundle ID, not affected by the access group.
        // We'll maintain that specific logic for service name derivation.
        if let bundleId = Bundle.main.bundleIdentifier {
            self.service = "\(bundleId).BiometricPreferences"
        } else {
            // Fallback if bundleId is somehow nil (should not happen in normal app execution)
            self.service = "ASimpleAuthKit.BiometricPreferences.Default"
        }

        print("BiometricPreferenceManager: Initialized with service: \(self.service), accessGroup: \(self.keychainAccessGroup ?? "nil")")
    }

    // MARK: - Public Interface

    public var isBiometricEnabled: Bool {
        get async {
            return await getBoolValue(for: KeychainKey.biometricEnabled) ?? false
        }
    }

    public func setBiometricEnabled(_ enabled: Bool) async {
        await setBoolValue(enabled, for: KeychainKey.biometricEnabled)
        print("BiometricPreferenceManager: Biometric enabled set to \(enabled)")
    }

    public var lastAuthenticatedUserID: String? {
        get async {
            return await getStringValue(for: KeychainKey.lastAuthenticatedUserID)
        }
    }

    public func setLastAuthenticatedUserID(_ userID: String?) async {
        if let userID = userID {
            await setStringValue(userID, for: KeychainKey.lastAuthenticatedUserID)
        } else {
            await removeValue(for: KeychainKey.lastAuthenticatedUserID)
        }
        print("BiometricPreferenceManager: Last authenticated user ID set to \(userID ?? "nil")")
    }

    public func shouldRequireBiometrics(for userID: String) async -> Bool {
        let isEnabled = await isBiometricEnabled
        let lastUserID = await lastAuthenticatedUserID

        let shouldRequire = isEnabled && lastUserID == userID
        print("BiometricPreferenceManager: Should require biometrics for \(userID): \(shouldRequire) (enabled: \(isEnabled), lastUser: \(lastUserID ?? "nil"))")
        return shouldRequire
    }

    public func clearAllPreferences() async {
        await removeValue(for: KeychainKey.biometricEnabled)
        await removeValue(for: KeychainKey.lastAuthenticatedUserID)
        print("BiometricPreferenceManager: Cleared all preferences")
    }

    public func recordSuccessfulBiometricAuth(for userID: String) async {
        await setBiometricEnabled(true)
        await setLastAuthenticatedUserID(userID)
        print("BiometricPreferenceManager: Recorded successful biometric auth for \(userID)")
    }

    // MARK: - Private Keychain Operations

    private func createBaseQuery(for key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]

        if let accessGroup = keychainAccessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        return query
    }

    private func setBoolValue(_ value: Bool, for key: String) async {
        let stringValue = value ? "true" : "false"
        await setStringValue(stringValue, for: key)
    }

    private func getBoolValue(for key: String) async -> Bool? {
        guard let stringValue = await getStringValue(for: key) else { return nil }
        return stringValue == "true"
    }

    private func setStringValue(_ value: String, for key: String) async {
        await Task.detached { [service = self.service, keychainAccessGroup = self.keychainAccessGroup] in
            guard let data = value.data(using: .utf8) else {
                print("BiometricPreferenceManager: Failed to encode value for key \(key)")
                return
            }

            var query = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: key
            ] as [String: Any]

            if let accessGroup = keychainAccessGroup {
                query[kSecAttrAccessGroup as String] = accessGroup
            }

            // Delete existing item first
            let deleteStatus = SecItemDelete(query as CFDictionary)
            if deleteStatus != errSecSuccess && deleteStatus != errSecItemNotFound {
                print("BiometricPreferenceManager: Warning - failed to delete existing item for key \(key): \(deleteStatus)")
            }

            // Add new item
            query[kSecValueData as String] = data
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly // Good default

            let addStatus = SecItemAdd(query as CFDictionary, nil)
            if addStatus != errSecSuccess {
                print("BiometricPreferenceManager: Failed to save value for key \(key): \(addStatus)")
            }
        }.value
    }

    private func getStringValue(for key: String) async -> String? {
        return await Task.detached { [service = self.service, keychainAccessGroup = self.keychainAccessGroup] in
            var query = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: key,
                kSecReturnData as String: kCFBooleanTrue!,
                kSecMatchLimit as String: kSecMatchLimitOne
            ] as [String: Any]

            if let accessGroup = keychainAccessGroup {
                query[kSecAttrAccessGroup as String] = accessGroup
            }

            var dataTypeRef: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)

            if status == errSecSuccess {
                guard let data = dataTypeRef as? Data,
                    let value = String(data: data, encoding: .utf8) else {
                    print("BiometricPreferenceManager: Failed to decode value for key \(key)")
                    return nil
                }
                return value
            } else if status != errSecItemNotFound {
                print("BiometricPreferenceManager: Failed to retrieve value for key \(key): \(status)")
            }

            return nil
        }.value
    }

    private func removeValue(for key: String) async {
        await Task.detached { [service = self.service, keychainAccessGroup = self.keychainAccessGroup] in
            var query = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: key
            ] as [String: Any]

            if let accessGroup = keychainAccessGroup {
                query[kSecAttrAccessGroup as String] = accessGroup
            }

            let status = SecItemDelete(query as CFDictionary)
            if status != errSecSuccess && status != errSecItemNotFound {
                print("BiometricPreferenceManager: Failed to remove value for key \(key): \(status)")
            }
        }.value
    }
}
