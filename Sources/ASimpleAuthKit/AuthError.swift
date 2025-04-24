import Foundation
import LocalAuthentication // For LAError constants
import FirebaseAuth // For AuthErrorCode constants

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
    case firebaseUIError(String)
    case firebaseAuthError(FirebaseErrorData)
    case accountLinkingError(String)
    case mergeConflictError(String)
    case accountLinkingRequired(email: String)
    case mergeConflictRequired
    case missingLinkingInfo

    public static func == (lhs: AuthError, rhs: AuthError) -> Bool {
        switch (lhs, rhs) {
        case (.cancelled, .cancelled): return true
        case (.unknown, .unknown): return true
        case (.configurationError(let lMsg), .configurationError(let rMsg)): return lMsg == rMsg
        case (.keychainError(let lStatus), .keychainError(let rStatus)): return lStatus == rStatus
        case (.biometricsNotAvailable, .biometricsNotAvailable): return true
        case (.biometricsFailed(let lCode), .biometricsFailed(let rCode)): return lCode == rCode
        case (.firebaseUIError(let lMsg), .firebaseUIError(let rMsg)): return lMsg == rMsg
        case (.firebaseAuthError(let lData), .firebaseAuthError(let rData)): return lData == rData
        case (.accountLinkingError(let lMsg), .accountLinkingError(let rMsg)): return lMsg == rMsg
        case (.mergeConflictError(let lMsg), .mergeConflictError(let rMsg)): return lMsg == rMsg
        case (.accountLinkingRequired(let lEmail), .accountLinkingRequired(let rEmail)): return lEmail == rEmail
        case (.mergeConflictRequired, .mergeConflictRequired): return true
        case (.missingLinkingInfo, .missingLinkingInfo): return true
        default: return false // Handles mismatching types
        }
    }

    public var localizedDescription: String {
        switch self {
        case .cancelled: return "Authentication was cancelled."
        case .unknown: return "An unknown authentication error occurred."
        case .configurationError(let m): return "Configuration Error: \(m)"
        case .keychainError(let s): return "Keychain error (Code: \(s))."
        case .biometricsNotAvailable: return "Biometric auth not available."
        case .biometricsFailed(let c): return "Biometric auth failed (\(c?.rawValue ?? -1))." // Simplified
        case .firebaseUIError(let m): return "Sign-in UI issue: \(m)"
        case .firebaseAuthError(let d): // Simplified for brevity, restore full logic if needed
            if d.domain == AuthErrorDomain && d.code == AuthErrorCode.credentialAlreadyInUse.rawValue { return "Sign-in method already linked." }; return "Auth error: \(d.message) (\(d.code))"
        case .accountLinkingError(let m): return "Account Linking Error: \(m)"
        case .mergeConflictError(let m): return "Account Conflict: \(m)"
        case .accountLinkingRequired(let email): return "Internal Error: Account linking required for email \(email)."
        case .mergeConflictRequired: return "Internal Error: Merge conflict state triggered."
        case .missingLinkingInfo: return "Internal Error: Missing info."
        }
    }

    // Helper initializers remain the same
    static func makeFirebaseAuthError(_ error: Error) -> AuthError {
        let e = error as NSError; return .firebaseAuthError(FirebaseErrorData(code: e.code, domain: e.domain, message: error.localizedDescription))
    }
    static func makeBiometricsFailedError(_ error: Error?) -> AuthError {
        return .biometricsFailed((error as? LAError)?.code)
    }
}
