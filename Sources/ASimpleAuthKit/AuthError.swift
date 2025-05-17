import Foundation
import LocalAuthentication // For LAError constants
import FirebaseAuth // For AuthErrorCode constants and AuthCredential

// Define a Sendable struct to hold Firebase error details safely across actors
public struct FirebaseErrorData: Error, Equatable, Sendable {
    public let code: Int
    public let domain: String
    public let message: String // Store the localized description

    public static func == (lhs: FirebaseErrorData, rhs: FirebaseErrorData) -> Bool {
        return lhs.code == rhs.code && lhs.domain == rhs.domain
    }
}

public enum AuthError: Error, Equatable, Sendable {
    case cancelled
    case unknown
    case configurationError(String)
    case keychainError(OSStatus)
    case biometricsNotAvailable
    case biometricsFailed(LAError.Code?)
    case firebaseAuthError(FirebaseErrorData)
    case accountLinkingError(String) // General error during linking process
    case mergeConflictError(String) // General error during merge process
    case accountLinkingRequired(email: String, pendingCredential: AuthCredential?) // If an account exists with this email, here's the credential the user just tried
    case mergeConflictRequired(existingCredential: AuthCredential) // If a merge conflict occurs
    case missingLinkingInfo
    case providerSpecificError(provider: String, underlyingError: FirebaseErrorData?) // For errors from GoogleSignIn, AppleSignIn etc.
    case reauthenticationRequired(providerId: String?)


    public static func == (lhs: AuthError, rhs: AuthError) -> Bool {
        switch (lhs, rhs) {
        case (.cancelled, .cancelled): return true
        case (.unknown, .unknown): return true
        case (.configurationError(let lMsg), .configurationError(let rMsg)): return lMsg == rMsg
        case (.keychainError(let lStatus), .keychainError(let rStatus)): return lStatus == rStatus
        case (.biometricsNotAvailable, .biometricsNotAvailable): return true
        case (.biometricsFailed(let lCode), .biometricsFailed(let rCode)): return lCode == rCode
        case (.firebaseAuthError(let lData), .firebaseAuthError(let rData)): return lData == rData
        case (.accountLinkingError(let lMsg), .accountLinkingError(let rMsg)): return lMsg == rMsg
        case (.mergeConflictError(let lMsg), .mergeConflictError(let rMsg)): return lMsg == rMsg
        case (.accountLinkingRequired(let lEmail, let lCred), .accountLinkingRequired(let rEmail, let rCred)):
            // AuthCredential doesn't conform to Equatable by default, so we can't directly compare them.
            // For now, compare based on email. If more specific comparison for credential is needed,
            // we'd need to compare properties of AuthCredential if possible, or rely on context.
            // Often, the presence of a credential vs nil is enough for logic.
            return lEmail == rEmail && (lCred == nil && rCred == nil || lCred != nil && rCred != nil)
        case (.mergeConflictRequired(let lCred), .mergeConflictRequired(let rCred)):
            // Similar to above, AuthCredential comparison is tricky.
            // For now, consider them equal if both are mergeConflictRequired.
            return true // Or compare provider IDs if useful: lCred.provider == rCred.provider
        case (.missingLinkingInfo, .missingLinkingInfo): return true
        case (.providerSpecificError(let lProv, let lErr), .providerSpecificError(let rProv, let rErr)):
            return lProv == rProv && lErr == rErr
        default: return false
        }
    }

    public var localizedDescription: String {
        switch self {
        case .cancelled: return "Authentication was cancelled."
        case .unknown: return "An unknown authentication error occurred."
        case .configurationError(let m): return "Configuration Error: \(m)"
        case .keychainError(let s): return "Keychain error (Code: \(s))."
        case .biometricsNotAvailable: return "Biometric authentication is not available on this device."
        case .biometricsFailed: return "Biometric authentication failed."
        case .firebaseAuthError(let d):
            if d.domain == AuthErrorDomain {
                switch d.code {
                case AuthErrorCode.wrongPassword.rawValue:
                    return "Incorrect password. Please try again."
                case AuthErrorCode.userNotFound.rawValue:
                    return "No account found with this email address."
                case AuthErrorCode.emailAlreadyInUse.rawValue:
                    // This specific message might be overridden by how we handle it (guiding to link)
                    return "This email address is already in use by another account."
                case AuthErrorCode.credentialAlreadyInUse.rawValue:
                    return "This sign-in method is already linked to an account, possibly a different one."
                case AuthErrorCode.networkError.rawValue:
                    return "A network error occurred. Please check your connection and try again."
                case AuthErrorCode.tooManyRequests.rawValue:
                    return "We have detected too many requests from your device. Please try again later."
                default:
                    return "Authentication error: \(d.message) (Code: \(d.code))"
                }
            }
            return "Authentication error: \(d.message) (Code: \(d.code))"
        case .accountLinkingError(let m): return "Account Linking Error: \(m)"
        case .mergeConflictError(let m): return "Account Merge Conflict: \(m)"
        case .accountLinkingRequired(let email, _):
            return "An account already exists for \(email). Please sign in with your existing method to link."
        case .mergeConflictRequired:
            return "An account conflict occurred. Please resolve to continue."
        case .missingLinkingInfo: return "Internal Error: Missing information required for account linking."
        case .providerSpecificError(let provider, let underlyingError):
            let baseMessage = "\(provider) sign-in failed."
            if let errMsg = underlyingError?.message, !errMsg.isEmpty {
                return "\(baseMessage) \(errMsg)"
            }
            return baseMessage
        case .reauthenticationRequired:
            return "Reauthentication required. App UI needs to handle this flow."
        }
    }

    static func makeFirebaseAuthError(_ error: Error) -> AuthError {
        let e = error as NSError
        return .firebaseAuthError(FirebaseErrorData(code: e.code, domain: e.domain, message: error.localizedDescription))
    }

    static func makeBiometricsFailedError(_ error: Error?) -> AuthError {
        // We don't need the specific LAError.Code for the public message.
        return .biometricsFailed(nil)
    }

    static func makeProviderSpecificError(provider: String, error: Error?) -> AuthError {
        if let nsError = error as NSError? {
            return .providerSpecificError(provider: provider, underlyingError: FirebaseErrorData(code: nsError.code, domain: nsError.domain, message: nsError.localizedDescription))
        }
        return .providerSpecificError(provider: provider, underlyingError: nil)
    }
}
