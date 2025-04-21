// Sources/AuthKit/Internal/BiometricAuthenticator.swift
import Foundation
import LocalAuthentication

internal class BiometricAuthenticator {
    private let context = LAContext()
    private var error: NSError?

    var isBiometricsAvailable: Bool {
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    var biometryTypeString: String {
        switch context.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .none: return "Biometrics"
        @unknown default: return "Biometrics"
        }
    }

    func authenticate(reason: String, completion: @escaping (Result<Void, AuthError>) -> Void) {
        guard isBiometricsAvailable else {
            completion(.failure(.biometricsNotAvailable(error)))
            return
        }

        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, evaluateError in
            DispatchQueue.main.async {
                if success {
                    completion(.success(()))
                } else {
                    let authError = evaluateError as? LAError
                    completion(.failure(.biometricsFailed(authError)))
                }
            }
        }
    }
}