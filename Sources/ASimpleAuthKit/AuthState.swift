import Foundation
import FirebaseAuth

// Simple User struct representing the authenticated user
public struct AuthUser: Equatable, Sendable {
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

    // Internal initializer for Testing
    internal init(uid: String, email: String?, displayName: String?, isAnonymous: Bool, providerID: String?) {
        self.uid = uid
        self.email = email
        self.displayName = displayName
        self.isAnonymous = isAnonymous
        self.providerID = providerID
    }

    public static func createPreviewUser(
        uid: String = "previewUID",
        email: String? = "preview@example.com",
        displayName: String? = "Preview User",
        isAnonymous: Bool = false,
        providerID: String? = "password"
    ) -> AuthUser {
        return AuthUser(uid: uid, email: email, displayName: displayName, isAnonymous: isAnonymous, providerID: providerID)
    }

    public static func == (lhs: AuthUser, rhs: AuthUser) -> Bool {
        return lhs.uid == rhs.uid // Compare only UID for equality
    }
}

public enum AuthState: Equatable, Sendable {
    case signedOut
    case authenticating(String?)
    case requiresBiometrics
    case signedIn(AuthUser)
    case requiresAccountLinking(email: String, attemptedProviderId: String?)
    case emailInUseSuggestSignIn(email: String)
    case requiresMergeConflictResolution

    public static func == (lhs: AuthState, rhs: AuthState) -> Bool {
        switch (lhs, rhs) {
        case (.signedOut, .signedOut): return true
        case (.authenticating(let lMsg), .authenticating(let rMsg)): return lMsg == rMsg
        case (.requiresBiometrics, .requiresBiometrics): return true
        case (.signedIn(let lUser), .signedIn(let rUser)): return lUser.uid == rUser.uid
        case (.requiresAccountLinking(let lEmail, let lProvider), .requiresAccountLinking(let rEmail, let rProvider)):
            return lEmail == rEmail && lProvider == rProvider
        case (.requiresMergeConflictResolution, .requiresMergeConflictResolution):
            return true
        default: return false
        }
    }

    public var isAuthenticating: Bool {
        if case .authenticating = self { return true }
        return false
    }
//
//    public var allowsSignInAttempt: Bool {
//        switch self {
//        case .signedOut, .requiresBiometrics, .requiresAccountLinking, .emailInUseSuggestSignIn, .requiresMergeConflictResolution: return true
//        case .authenticating, .signedIn: return false
//        }
//    }

    public var isPendingResolution: Bool {
        switch self {
        case .requiresAccountLinking, .requiresMergeConflictResolution: return true
        default: return false
        }
    }

    public var isSignedIn: Bool {
        if case .signedIn = self {
            return true
        }
        return false
    }

    public var isSignedOut: Bool {
        return self == .signedOut
    }
}
