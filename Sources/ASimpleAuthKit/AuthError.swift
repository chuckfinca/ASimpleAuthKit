import Foundation
import LocalAuthentication // For LAError constants
import FirebaseAuth       // For AuthErrorCode constants

public enum AuthError: Error, Equatable {
    case cancelled
    case unknown
    case configurationError(String)
    case keychainError(OSStatus)
    case biometricsNotAvailable(NSError?) // Can include the underlying LAError if available
    case biometricsFailed(LAError?)       // Include the specific LAError code
    case firebaseUIError(String)          // Errors specifically from FirebaseUI library/flow
    case firebaseAuthError(Error)         // Wraps an underlying FirebaseAuth error
    case accountLinkingError(String)      // Generic linking process errors
    case mergeConflictError(String)       // Generic merge conflict process errors

    // Specific errors thrown by FirebaseAuthenticator to trigger state changes in AuthService
    case accountLinkingRequired // Signals the state transition needed
    case mergeConflictRequired  // Signals the state transition needed
    case missingLinkingInfo     // Error if required info isn't available for linking/merge

    // Equatable implementation
    public static func == (lhs: AuthError, rhs: AuthError) -> Bool {
        switch (lhs, rhs) {
        case (.cancelled, .cancelled): return true
        case (.unknown, .unknown): return true
        case (.configurationError(let lMsg), .configurationError(let rMsg)): return lMsg == rMsg
        case (.keychainError(let lStatus), .keychainError(let rStatus)): return lStatus == rStatus
        case (.biometricsNotAvailable, .biometricsNotAvailable): return true // Ignore associated error
        case (.biometricsFailed(let lErr), .biometricsFailed(let rErr)): return lErr?.code == rErr?.code // Compare LAError codes
        case (.firebaseUIError(let lMsg), .firebaseUIError(let rMsg)): return lMsg == rMsg
        case (.firebaseAuthError(let lErr), .firebaseAuthError(let rErr)):
             // Basic comparison for underlying errors (might not be fully accurate)
             return (lErr as NSError).domain == (rErr as NSError).domain && (lErr as NSError).code == (rErr as NSError).code
        case (.accountLinkingError(let lMsg), .accountLinkingError(let rMsg)): return lMsg == rMsg
        case (.mergeConflictError(let lMsg), .mergeConflictError(let rMsg)): return lMsg == rMsg
        case (.accountLinkingRequired, .accountLinkingRequired): return true
        case (.mergeConflictRequired, .mergeConflictRequired): return true
        case (.missingLinkingInfo, .missingLinkingInfo): return true
        default: return false
        }
    }

    // Provide localized descriptions for user-facing errors
    public var localizedDescription: String {
        switch self {
        case .cancelled:
            return "Authentication was cancelled."
        case .unknown:
            return "An unknown authentication error occurred."
        case .configurationError(let message):
            return "Configuration Error: \(message)"
        case .keychainError(let status):
            // You might want to map common OSStatus codes to messages
            return "A keychain error occurred (\(status))."
        case .biometricsNotAvailable:
            return "Biometric authentication is not available on this device."
        case .biometricsFailed(let laError):
            // Provide specific LAError descriptions if available
            if let laError = laError {
                 switch laError.code {
                 case LAError.authenticationFailed: return "Biometric authentication failed."
                 case LAError.userCancel: return "Biometric authentication cancelled."
                 case LAError.userFallback: return "Password/passcode entry requested." // User chose fallback
                 case LAError.biometryNotAvailable: return "Biometrics not available."
                 case LAError.biometryLockout: return "Too many failed attempts. Biometrics locked out."
                 case LAError.biometryNotEnrolled: return "Biometrics not set up on this device."
                 default: return "Biometric authentication failed (\(laError.code))."
                 }
            }
            return "Biometric authentication failed."
        case .firebaseUIError(let message):
            return "An issue occurred with the sign-in interface: \(message)"
        case .firebaseAuthError(let error):
            // Inspect the underlying Firebase error
            let nsError = error as NSError
            if nsError.domain == AuthErrorDomain {
                switch nsError.code {
                case AuthErrorCode.wrongPassword.rawValue:
                    return "Incorrect password. Please try again."
                case AuthErrorCode.invalidEmail.rawValue:
                    return "The email address is badly formatted."
                case AuthErrorCode.userNotFound.rawValue:
                    return "No account found with this email address."
                case AuthErrorCode.emailAlreadyInUse.rawValue:
                    return "This email address is already in use by another account."
                case AuthErrorCode.networkError.rawValue:
                    return "Could not connect to the server. Please check your network connection."
                case AuthErrorCode.tooManyRequests.rawValue:
                    return "Too many requests. Please try again later."
                case AuthErrorCode.requiresRecentLogin.rawValue:
                     return "This action requires you to have signed in recently. Please sign out and sign back in."
                // Add more specific Firebase error codes as needed
                default:
                    // Use Firebase's own description as a fallback
                    return error.localizedDescription // Firebase often provides good descriptions
                }
            }
            // Fallback for non-FirebaseAuth errors wrapped here
            return "An unexpected error occurred: \(error.localizedDescription)"
        case .accountLinkingError(let message):
            return "Account Linking Error: \(message)"
        case .mergeConflictError(let message):
             return "Account Conflict: \(message)" // E.g., trying to link conflicting anonymous data
        case .accountLinkingRequired:
            // This shouldn't be shown to the user directly
            return "Internal Error: Account linking state triggered."
        case .mergeConflictRequired:
            // This shouldn't be shown to the user directly
            return "Internal Error: Merge conflict state triggered."
        case .missingLinkingInfo:
             // This shouldn't be shown to the user directly
            return "Internal Error: Missing required information for operation."
        }
    }
}