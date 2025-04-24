import Foundation
import FirebaseAuth

// Simple User struct representing the authenticated user
public struct User: Equatable, Sendable {
    public let uid: String
    public let email: String?
    public let displayName: String?
    public let isAnonymous: Bool
    public let providerID: String?

    init(firebaseUser: FirebaseAuth.User) {
        self.uid = firebaseUser.uid
        self.email = firebaseUser.email
        self.displayName = firebaseUser.displayName
        self.isAnonymous = firebaseUser.isAnonymous
        self.providerID = firebaseUser.providerData.first?.providerID
    }
}

public enum AuthState: Equatable, Sendable {
    case signedOut
    case authenticating(String?)
    case requiresBiometrics
    case signedIn(User)
    case requiresAccountLinking(email: String, existingProviders: [String])
    case requiresMergeConflictResolution

    public static func == (lhs: AuthState, rhs: AuthState) -> Bool {
        switch (lhs, rhs) {
        case (.signedOut, .signedOut): return true
        case (.authenticating(let lMsg), .authenticating(let rMsg)): return lMsg == rMsg
        case (.requiresBiometrics, .requiresBiometrics): return true
        case (.signedIn(let lUser), .signedIn(let rUser)): return lUser.uid == rUser.uid
        case (.requiresAccountLinking(let lEmail, let lProviders), .requiresAccountLinking(let rEmail, let rProviders)):
            return lEmail == rEmail && lProviders.sorted() == rProviders.sorted()
        case (.requiresMergeConflictResolution, .requiresMergeConflictResolution):
            return true
        default: return false
        }
    }

    var allowsSignInAttempt: Bool {
        switch self {
        case .signedOut, .requiresBiometrics, .requiresAccountLinking, .requiresMergeConflictResolution: return true
        case .authenticating, .signedIn: return false
        }
    }

    var isPendingResolution: Bool {
        switch self {
        case .requiresAccountLinking, .requiresMergeConflictResolution: return true
        default: return false
        }
    }
}
