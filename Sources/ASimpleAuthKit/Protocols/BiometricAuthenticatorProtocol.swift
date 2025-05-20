import Foundation

/// Protocol defining the interface for biometric authentication checks.
@MainActor
internal protocol BiometricAuthenticatorProtocol {
    /// Checks if biometric authentication (Face ID, Touch ID) is available and configured on the device.
    var isBiometricsAvailable: Bool { get }

    /// A user-friendly string representing the available biometry type (e.g., "Face ID", "Touch ID").
    var biometryTypeString: String { get }

    /// Attempts to authenticate the user using biometrics.
    /// - Parameter reason: The localized reason string displayed to the user.
    /// - Parameter completion: A closure called with the result (`.success` or `.failure(AuthError)`).
    func authenticate(reason: String, completion: @escaping (Result<Void, AuthError>) -> Void)
}
