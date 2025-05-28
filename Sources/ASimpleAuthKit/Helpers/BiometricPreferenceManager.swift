import Foundation
import Security

/// Manages per-device biometric authentication preferences
/// This is separate from user session management and persists across sign-outs
@MainActor
public class BiometricPreferenceManager {
    
    // MARK: - Singleton
    public static let shared = BiometricPreferenceManager()
    
    // MARK: - Private Properties
    private let service: String
    private let keychainAccessGroup: String?
    
    // Keychain keys
    private enum KeychainKey {
        static let biometricEnabled = "biometric_enabled"
        static let lastAuthenticatedUserID = "biometric_last_user_id"
    }
    
    // MARK: - Initialization
    
    private init() {
        // Use bundle identifier as service name
        if let bundleId = Bundle.main.bundleIdentifier {
            self.service = "\(bundleId).BiometricPreferences"
        } else {
            self.service = "ASimpleAuthKit.BiometricPreferences"
        }
        self.keychainAccessGroup = nil // Could be made configurable if needed
        print("BiometricPreferenceManager: Initialized with service: \(service)")
    }
    
    /// Initialize with custom access group (for app groups)
    public convenience init(keychainAccessGroup: String?) {
        self.init()
        // Would need to modify private init to accept parameters - for now using default
    }
    
    // MARK: - Public Interface
    
    /// Check if biometric authentication is enabled for this device
    public var isBiometricEnabled: Bool {
        get async {
            return await getBoolValue(for: KeychainKey.biometricEnabled) ?? false
        }
    }
    
    /// Enable or disable biometric authentication for this device
    public func setBiometricEnabled(_ enabled: Bool) async {
        await setBoolValue(enabled, for: KeychainKey.biometricEnabled)
        print("BiometricPreferenceManager: Biometric enabled set to \(enabled)")
    }
    
    /// Get the last user ID that was authenticated with biometrics
    /// This is used to ensure biometrics only work for the expected user
    public var lastAuthenticatedUserID: String? {
        get async {
            return await getStringValue(for: KeychainKey.lastAuthenticatedUserID)
        }
    }
    
    /// Set the last user ID that authenticated with biometrics
    public func setLastAuthenticatedUserID(_ userID: String?) async {
        if let userID = userID {
            await setStringValue(userID, for: KeychainKey.lastAuthenticatedUserID)
        } else {
            await removeValue(for: KeychainKey.lastAuthenticatedUserID)
        }
        print("BiometricPreferenceManager: Last authenticated user ID set to \(userID ?? "nil")")
    }
    
    /// Check if biometric authentication should be required for a specific user
    /// Returns true if biometrics are enabled AND the user ID matches the last authenticated user
    public func shouldRequireBiometrics(for userID: String) async -> Bool {
        let isEnabled = await isBiometricEnabled
        let lastUserID = await lastAuthenticatedUserID
        
        let shouldRequire = isEnabled && lastUserID == userID
        print("BiometricPreferenceManager: Should require biometrics for \(userID): \(shouldRequire) (enabled: \(isEnabled), lastUser: \(lastUserID ?? "nil"))")
        return shouldRequire
    }
    
    /// Clear all biometric preferences (useful for sign-out or reset scenarios)
    public func clearAllPreferences() async {
        await removeValue(for: KeychainKey.biometricEnabled)
        await removeValue(for: KeychainKey.lastAuthenticatedUserID)
        print("BiometricPreferenceManager: Cleared all preferences")
    }
    
    /// Update preferences after successful biometric authentication
    /// This ensures the user ID is current and biometrics remain enabled
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
        await Task.detached { [service, keychainAccessGroup] in
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
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            
            let addStatus = SecItemAdd(query as CFDictionary, nil)
            if addStatus != errSecSuccess {
                print("BiometricPreferenceManager: Failed to save value for key \(key): \(addStatus)")
            }
        }.value
    }
    
    private func getStringValue(for key: String) async -> String? {
        return await Task.detached { [service, keychainAccessGroup] in
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
        await Task.detached { [service, keychainAccessGroup] in
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