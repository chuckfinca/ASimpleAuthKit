import Foundation
import FirebaseAuth

// Simple User struct representing the authenticated user
public struct User: Equatable {
    public let uid: String
    public let email: String?
    public let displayName: String?
    public let isAnonymous: Bool // Useful if supporting anonymous upgrade
    public let providerID: String? // The primary provider ID (e.g., "password", "google.com")

    init(firebaseUser: FirebaseAuth.User) {
        self.uid = firebaseUser.uid
        self.email = firebaseUser.email
        self.displayName = firebaseUser.displayName
        self.isAnonymous = firebaseUser.isAnonymous
        // Get the primary provider ID (may not always be the most recent one if linked)
        self.providerID = firebaseUser.providerData.first?.providerID
    }
}

public enum AuthState: Equatable {
    case signedOut
    case authenticating(String?) // Optional message like "Linking account..."
    case requiresBiometrics
    case signedIn(User)

    // NEW STATES:
    /// Indicates that the user tried to sign in with a new provider for an existing email.
    /// The UI should prompt the user to sign in with one of the `existingProviders` to link the accounts.
    case requiresAccountLinking(email: String, existingProviders: [String])

    /// Indicates that an anonymous user tried to link to an existing account, causing a conflict.
    /// The UI should warn the user that anonymous data might be lost and confirm signing into the existing account.
    case requiresMergeConflictResolution

    // Equatable implementation
    public static func == (lhs: AuthState, rhs: AuthState) -> Bool {
        switch (lhs, rhs) {
        case (.signedOut, .signedOut): return true
        case (.authenticating(let lMsg), .authenticating(let rMsg)): return lMsg == rMsg
        case (.requiresBiometrics, .requiresBiometrics): return true
        case (.signedIn(let lUser), .signedIn(let rUser)): return lUser.uid == rUser.uid // Basic equality check on UID
        case (.requiresAccountLinking(let lEmail, let lProviders), .requiresAccountLinking(let rEmail, let rProviders)):
            return lEmail == rEmail && lProviders == rProviders
        case (.requiresMergeConflictResolution, .requiresMergeConflictResolution):
            return true
        default: return false
        }
    }

    /// Can a new sign-in attempt be started from this state?
    /// Allows starting sign-in if resolving conflicts.
    var allowsSignInAttempt: Bool {
        switch self {
        case .signedOut, .requiresBiometrics, .requiresAccountLinking, .requiresMergeConflictResolution:
            return true
        case .authenticating, .signedIn:
            return false
        }
    }

    /// Is the state waiting for user action to resolve linking or merge conflict?
    var isPendingResolution: Bool {
         switch self {
         case .requiresAccountLinking, .requiresMergeConflictResolution:
             return true
         default:
             return false
         }
     }
}