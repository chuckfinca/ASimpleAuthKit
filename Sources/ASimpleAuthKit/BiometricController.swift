import Foundation

/// High-level controller for managing biometric authentication preferences and flows
/// Combines AuthService capabilities with BiometricPreferenceManager storage
@MainActor
public class BiometricController: ObservableObject {

    // MARK: - Dependencies
    private let authService: any AuthServiceProtocol
    private let preferenceManager: BiometricPreferenceManager

    // MARK: - Published State
    @Published public private(set) var isBiometricEnabled: Bool = false
    @Published public private(set) var isCheckingPreferences: Bool = false

    // MARK: - Computed Properties

    /// Whether the device supports biometric authentication
    public var isBiometricsAvailable: Bool {
        return authService.isBiometricsAvailable
    }

    /// Display string for the available biometry type ("Face ID", "Touch ID", "Biometrics")
    public var biometryTypeString: String {
        return authService.biometryTypeString
    }

    // MARK: - Initialization

    public init(authService: any AuthServiceProtocol, preferenceManager: BiometricPreferenceManager = .shared) {
        self.authService = authService
        self.preferenceManager = preferenceManager

        Task {
            await loadPreferences()
        }
    }

    // MARK: - Public Interface

    /// Load biometric preferences from storage
    public func loadPreferences() async {
        isCheckingPreferences = true
        let enabled = await preferenceManager.isBiometricEnabled
        await MainActor.run {
            self.isBiometricEnabled = enabled
            self.isCheckingPreferences = false
        }
    }

    public func enableBiometrics() async throws {
        guard isBiometricsAvailable else {
            throw AuthError.biometricsNotAvailable
        }

        // Test biometric authentication first
        try await authService.testBiometricAuthentication()

        // If test succeeds, enable the preference
        await preferenceManager.setBiometricEnabled(true)

        // Update local state
        await MainActor.run {
            self.isBiometricEnabled = true
        }

        print("BiometricController: Biometric authentication enabled successfully")
    }

    public func disableBiometrics() async {
        await preferenceManager.setBiometricEnabled(false)
        await preferenceManager.setLastAuthenticatedUserID(nil)

        await MainActor.run {
            self.isBiometricEnabled = false
        }

        print("BiometricController: Biometric authentication disabled")
    }

    public func shouldRequireBiometricsForCurrentSession() async -> Bool {
        guard isBiometricsAvailable else { return false }
        guard await preferenceManager.isBiometricEnabled else { return false }
        guard let currentUser = getCurrentUser() else { return false }

        // Check if this user previously used biometrics
        let lastUserID = await preferenceManager.lastAuthenticatedUserID
        let shouldRequire = lastUserID == currentUser.uid

        print("BiometricController: Should require biometrics for current session: \(shouldRequire)")
        return shouldRequire
    }

    public func requireBiometricAuthentication() {
        guard authService.state == .signedOut else {
            print("BiometricController: Cannot require biometric auth - not in signed out state")
            return
        }

        authService.requireBiometricAuthentication()
        print("BiometricController: Biometric authentication required")
    }

    public func handleSuccessfulBiometricAuth() async {
        guard let currentUser = getCurrentUser() else {
            print("BiometricController: Cannot handle successful biometric auth - no current user")
            return
        }

        await preferenceManager.recordSuccessfulBiometricAuth(for: currentUser.uid)
        print("BiometricController: Recorded successful biometric auth for user \(currentUser.uid)")
    }

    public func clearAllPreferences() async {
        await preferenceManager.clearAllPreferences()
        await MainActor.run {
            self.isBiometricEnabled = false
        }
        print("BiometricController: Cleared all biometric preferences")
    }

    // MARK: - Convenience Methods

    public func completeBiometricSetup() async throws {
        guard let currentUser = getCurrentUser() else {
            throw AuthError.configurationError("No current user for biometric setup")
        }

        // Enable biometrics (this tests biometric auth)
        try await enableBiometrics()

        // Associate with current user
        await preferenceManager.setLastAuthenticatedUserID(currentUser.uid)

        print("BiometricController: Completed biometric setup for user \(currentUser.uid)")
    }

    /// Check if the current user has biometric authentication set up
    public func isCurrentUserBiometricEnabled() async -> Bool {
        guard let currentUser = getCurrentUser() else { return false }
        return await preferenceManager.shouldRequireBiometrics(for: currentUser.uid)
    }

    // MARK: - Private Helpers

    private func getCurrentUser() -> AuthUser? {
        if case .signedIn(let user) = authService.state {
            return user
        }
        return nil
    }
}

// MARK: - Convenience Extensions

public extension BiometricController {

    /// Create a BiometricController with the provided AuthService
    static func create(with authService: any AuthServiceProtocol) -> BiometricController {
        return BiometricController(authService: authService)
    }
}
