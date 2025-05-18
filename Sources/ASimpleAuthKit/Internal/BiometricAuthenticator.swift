import Foundation
import LocalAuthentication

internal class BiometricAuthenticator: BiometricAuthenticatorProtocol {

    var isBiometricsAvailable: Bool {
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    var biometryTypeString: String {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)

        switch context.biometryType { case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        default: return "Biometrics"
        }
    }

    func authenticate(reason: String, completion: @escaping (Result<Void, AuthError>) -> Void) {
        let context = LAContext()
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else {
            completion(.failure(.biometricsNotAvailable))
            print("Biometric policy check failed: \(policyError?.localizedDescription ?? "Unknown")")
            return
        }

        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, evaluateError in
            DispatchQueue.main.async {
                if success {
                    completion(.success(()))
                }
                else {
                    completion(.failure(AuthError.makeBiometricsFailedError(evaluateError)))
                    print("Biometric eval failed: \(evaluateError?.localizedDescription ?? "Unknown")")
                }
            }
        }
    }
}
