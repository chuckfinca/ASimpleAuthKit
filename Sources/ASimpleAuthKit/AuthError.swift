import Foundation
import GoogleSignIn
import AuthenticationServices
import LocalAuthentication
@preconcurrency import FirebaseAuth // For AuthErrorCode constants. AuthCredential is not directly in Sendable errors.

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
    case accountLinkingError(String)
    case mergeConflictError(String)
    case accountLinkingRequired(email: String, attemptedProviderId: String?)
    case missingLinkingInfo
    case providerSpecificError(provider: String, underlyingError: FirebaseErrorData?)
    case reauthenticationRequired(providerId: String?)
    case helpfulInvalidCredential(email: String)
    case helpfulUserNotFound(email: String)


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
        case (.accountLinkingRequired(let lEmail, let lAttemptedId), .accountLinkingRequired(let rEmail, let rAttemptedId)):
            return lEmail == rEmail && lAttemptedId == rAttemptedId
        case (.missingLinkingInfo, .missingLinkingInfo): return true
        case (.providerSpecificError(let lProv, let lErr), .providerSpecificError(let rProv, let rErr)):
            return lProv == rProv && lErr == rErr
        case (.reauthenticationRequired(let lId), .reauthenticationRequired(let rId)):
            return lId == rId
        case (.helpfulInvalidCredential(let lEmail), .helpfulInvalidCredential(let rEmail)):
            return lEmail == rEmail
        case (.helpfulUserNotFound(let lEmail), .helpfulUserNotFound(let rEmail)):
            return lEmail == rEmail
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
        case .biometricsFailed(let code):
            if let code = code {
                switch code {
                case .userCancel:
                    return "Biometric authentication was canceled."
                case .userFallback:
                    return "Password option was selected instead of biometrics."
                case .biometryNotEnrolled:
                    return "Biometric authentication is not set up on this device."
                case .biometryLockout:
                    return "Biometric authentication is temporarily locked due to too many failed attempts."
                default:
                    return "Biometric authentication failed: \(code)."
                }
            }
            return "Biometric authentication failed."
        case .firebaseAuthError(let d):
            if d.domain == AuthErrorDomain {
                switch d.code {
                case AuthErrorCode.invalidCredential.rawValue:
                    return "Invalid credentials. Please check and try again."
                case AuthErrorCode.wrongPassword.rawValue:
                    return "Incorrect password. Please try again."
                case AuthErrorCode.userNotFound.rawValue:
                    return "No account found with this email address."
                case AuthErrorCode.emailAlreadyInUse.rawValue:
                    // This message might be less direct if we are guiding to link.
                    // The .accountLinkingRequired error will have a more specific message.
                    return "This email address is already in use by another account."
                case AuthErrorCode.credentialAlreadyInUse.rawValue:
                    // This could lead to mergeConflictError
                    return "This sign-in method is already linked to an account, possibly a different one."
                case AuthErrorCode.networkError.rawValue:
                    return "A network error occurred. Please check your connection and try again."
                case AuthErrorCode.tooManyRequests.rawValue:
                    return "We have detected too many requests from your device. Please try again later."
                case AuthErrorCode.invalidEmail.rawValue:
                    return "Please enter a valid email address."
                case AuthErrorCode.weakPassword.rawValue:
                    return "Password must be at least 6 characters long."
                case AuthErrorCode.userDisabled.rawValue:
                    return "This account has been disabled. Please contact support."
                case AuthErrorCode.operationNotAllowed.rawValue:
                    return "This sign-in method is not enabled. Please try a different method."
                case AuthErrorCode.expiredActionCode.rawValue:
                    return "This reset link has expired. Please request a new one."
                case AuthErrorCode.invalidActionCode.rawValue:
                    return "This reset link is invalid. Please request a new one."
                case AuthErrorCode.requiresRecentLogin.rawValue:
                    return "Please sign in again to continue."
                default:
                    return "Authentication error: \(d.message) (Code: \(d.code))"
                }
            }
            return "Authentication error: \(d.message) (Code: \(d.code))"

        case .accountLinkingError(let m): return "Account Linking Error: \(m)"
        case .mergeConflictError(let m): return "Account Merge Conflict: \(m)"
        case .accountLinkingRequired(let email, let attemptedProviderId):
            var message = "An account already exists for \(email)."
            if let provider = attemptedProviderId {
                let providerName = provider == "password" ? "Email/Password" : provider.capitalized
                message += " You attempted to sign in or sign up using \(providerName)."
            }
            message += " Please sign in with your existing method to link this account."
            return message

        case .missingLinkingInfo: return "Internal Error: Missing information required for account linking."
        case .providerSpecificError(let provider, let underlyingError):
            let baseMessage = "\(provider) sign-in failed."
            if let errMsg = underlyingError?.message, !errMsg.isEmpty {
                return "\(baseMessage) \(errMsg)"
            }
            return baseMessage
        case .reauthenticationRequired:
            return "Reauthentication required. App UI needs to handle this flow."
        case .helpfulInvalidCredential(let email):
            return "We couldn't sign you in with that password. You might have created your account using Google, Apple, or a different password. Try signing in with Google or Apple, or use 'Forgot Password' if you signed up with email."

        case .helpfulUserNotFound(let email):
            return "No account found for \(email). You can create a new account, or try signing in with Google or Apple if you've used those before."
        }
    }

    static func makeFirebaseAuthError(_ error: Error) -> AuthError {
        let e = error as NSError
        return .firebaseAuthError(FirebaseErrorData(code: e.code, domain: e.domain, message: error.localizedDescription))
    }

    static func makeBiometricsFailedError(_ error: Error?) -> AuthError {
        guard let error = error else {
            return .biometricsFailed(nil)
        }

        if let laError = error as? LAError {
            return .biometricsFailed(laError.code)
        }

        return .biometricsFailed(nil)
    }

    static func makeProviderSpecificError(provider: String, error: Error?) -> AuthError {
        guard let nsError = error as NSError? else {
            return .providerSpecificError(provider: provider, underlyingError: nil)
        }

        // Check for cancellation errors from any provider
        if (nsError.domain == kGIDSignInErrorDomain && nsError.code == GIDSignInError.canceled.rawValue) ||
            (nsError.domain == ASAuthorizationErrorDomain && nsError.code == ASAuthorizationError.canceled.rawValue) {
            return .cancelled
        }

        return .providerSpecificError(provider: provider, underlyingError: FirebaseErrorData(code: nsError.code, domain: nsError.domain, message: nsError.localizedDescription))
    }
}

// MARK: - Field Validation Support

public extension AuthError {
    enum ValidationField: String, CaseIterable, Sendable {
        case email
        case password
        case general
    }

    /// Returns the field that should be highlighted for this error, if any
    var affectedField: ValidationField? {
        switch self {
        case .firebaseAuthError(let data):
            switch data.code {
            case AuthErrorCode.invalidCredential.rawValue,
                 AuthErrorCode.wrongPassword.rawValue,
                 AuthErrorCode.userNotFound.rawValue:
                return .email // Show on email field for auth failures
            case AuthErrorCode.invalidEmail.rawValue:
                return .email
            case AuthErrorCode.weakPassword.rawValue:
                return .password
            default:
                return nil
            }
        case .accountLinkingRequired:
            return .email // Email field is the focus for linking issues
        case .helpfulInvalidCredential, .helpfulUserNotFound:
            return .general
        default:
            return nil
        }
    }

    /// Returns true if this error should show a red border on the password field
    var shouldHighlightPassword: Bool {
        switch self {
        case .firebaseAuthError(let data):
            switch data.code {
            case AuthErrorCode.invalidCredential.rawValue,
                 AuthErrorCode.wrongPassword.rawValue:
                return true // Highlight both email and password for credential failures
            case AuthErrorCode.weakPassword.rawValue:
                return true
            default:
                return false
            }
        default:
            return false
        }
    }
}
