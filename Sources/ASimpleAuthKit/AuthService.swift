import Foundation
import Combine
import FirebaseAuth
import UIKit // Needed for UIViewController in signIn

@MainActor
public class AuthService: ObservableObject, AuthServiceProtocol {
    @Published public private(set) var state: AuthState = .signedOut
    @Published public private(set) var lastError: AuthError? = nil

    private let config: AuthConfig
    private let firebaseAuthenticator: FirebaseAuthenticator
    private let biometricAuthenticator: BiometricAuthenticator
    private let secureStorage: SecureStorageProtocol
    private var authStateHandle: AuthStateDidChangeListenerHandle?
    private var cancellables = Set<AnyCancellable>()

    // To store context during linking flows
    private var emailForLinking: String?

    public init(config: AuthConfig) {
        self.config = config
        let storage = KeychainStorage()
        self.secureStorage = storage
        self.firebaseAuthenticator = FirebaseAuthenticator(config: config, secureStorage: storage)
        self.biometricAuthenticator = BiometricAuthenticator()

        print("AuthService: Initializing.")
        checkInitialState()

        authStateHandle = Auth.auth().addStateDidChangeListener { [weak self] (auth, firebaseUser) in
            print("AuthService: Firebase Auth state changed listener triggered. User: \(firebaseUser?.uid ?? "nil")")
            self?.handleAuthStateChange(firebaseUser: firebaseUser)
        }
    }

    deinit {
        if let handle = authStateHandle {
            Auth.auth().removeStateDidChangeListener(handle)
            print("AuthService: Removed Firebase Auth state listener.")
        }
         print("AuthService: Deinitialized.")
    }

    // MARK: - Public API

    public func signIn(from viewController: UIViewController) async {
        print("AuthService: signIn requested. Current state: \(state)")
        guard state.allowsSignInAttempt else {
             print("AuthService: Sign-in requested but state (\(state)) doesn't allow it.")
            return
        }

        // Reset state if starting fresh
        if state == .signedOut || state == .requiresBiometrics {
             resetForNewSignInAttempt()
        }

        let purposeMessage = state.isPendingResolution ? "Signing in to resolve conflict..." : "Starting sign in..."
        state = .authenticating(purposeMessage)
        lastError = nil // Clear previous errors at the start of an attempt

        do {
            let user = try await firebaseAuthenticator.presentSignInUI(from: viewController)
            // Handle the successful sign-in, including potential linking
            await completeSuccessfulSignIn(user: user)

        } catch let error as AuthError {
            // Handle specific AuthKit errors that dictate state transitions
            await handleSignInAuthError(error)
        } catch {
            // Handle other generic errors
            await handleSignInGenericError(error)
        }
    }

    public func signOut() {
         print("AuthService: signOut requested.")
        do {
            try Auth.auth().signOut()
            // State change handled by listener
            // Clean up local state immediately
            try secureStorage.clearLastUserID()
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
            lastError = nil
            print("AuthService: Sign out successful locally.")
            // Listener will set state = .signedOut
        } catch {
            print("AuthService: Sign out failed: \(error)")
            lastError = AuthError.firebaseAuthError(error) // Publish the error
            // Attempt to reset state anyway, listener might correct if needed
            state = .signedOut
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
        }
    }

    public func authenticateWithBiometrics(reason: String = "Sign in to your account") async {
        print("AuthService: authenticateWithBiometrics requested. Current state: \(state)")
        guard state == .requiresBiometrics else {
            print("AuthService Warning: Biometric authentication requested but state is not .requiresBiometrics.")
            return
        }
        guard let currentFirebaseUser = Auth.auth().currentUser else {
            print("AuthService Error: Biometrics required but no Firebase user found. Resetting state.")
            state = .signedOut // Correct state if Firebase user disappeared
            return
        }

        state = .authenticating(biometricAuthenticator.biometryTypeString)
        lastError = nil // Clear previous errors

        biometricAuthenticator.authenticate(reason: reason) { [weak self] result in
             guard let self = self else { return }
            switch result {
            case .success:
                print("AuthService: Biometric authentication successful.")
                // Double check the user hasn't changed somehow
                if let updatedUser = Auth.auth().currentUser, updatedUser.uid == currentFirebaseUser.uid {
                    self.state = .signedIn(User(firebaseUser: updatedUser))
                    // Optional: Update timestamp in keychain for last biometric success?
                } else {
                    print("AuthService Warning: User changed during biometric auth? Fallback to signed out.")
                     // This case is unlikely but possible if the auth state changed exactly during the prompt
                    self.state = .signedOut // Fallback if user mismatch
                }
            case .failure(let error):
                print("AuthService: Biometric authentication failed: \(error)")
                self.lastError = error // Publish the biometric error
                // Revert to requiresBiometrics to allow user retry or choose fallback
                self.state = .requiresBiometrics
            }
        }
    }

    // MARK: - Methods for Resolving Linking/Merge States (Called by UI)

    public func proceedWithMergeConflictResolution() async {
        print("AuthService: proceedWithMergeConflictResolution called. Current state: \(state)")
        guard state == .requiresMergeConflictResolution else {
            print("AuthService Warning: Proceed with merge conflict called but state is not .requiresMergeConflictResolution.")
            return
        }
        guard let existingCredential = firebaseAuthenticator.existingCredentialForMergeConflict else {
            print("AuthService Error: Missing existing credential for merge conflict resolution.")
            state = .signedOut // Reset state
            lastError = .missingLinkingInfo
            firebaseAuthenticator.clearTemporaryCredentials() // Ensure cleared
            return
        }

        state = .authenticating("Signing in to existing account...")
        lastError = nil

        do {
            let authResult = try await Auth.auth().signIn(with: existingCredential)
            // Success state will be handled by the auth state listener
            print("AuthService: Merge conflict resolved: Signed in as existing user \(authResult.user.uid). Listener will update state.")
            // Explicitly clear here as listener might take time or fail
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil // Ensure clear
            // Treat as successful sign-in for biometric check next time
            try? secureStorage.saveLastUserID(authResult.user.uid)
        } catch {
            print("AuthService Error: Failed to sign in with existing credential during merge conflict resolution: \(error)")
            lastError = .firebaseAuthError(error) // Publish the error
            state = .signedOut // Fallback on error
            firebaseAuthenticator.clearTemporaryCredentials() // Ensure cleared
            emailForLinking = nil
        }
    }

    public func cancelPendingAction() {
        print("AuthService: cancelPendingAction called. Current state: \(state)")
        guard state.isPendingResolution else {
             print("AuthService: Cancel pending action called but state is not pending.")
             return
        }
        print("AuthService: User cancelled pending action (linking/merge). Resetting state.")
        state = .signedOut
        lastError = nil
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
    }

    // MARK: - Private Helper Methods

    /// Resets temporary state before a new sign-in attempt.
    private func resetForNewSignInAttempt() {
        print("AuthService: Resetting for new sign-in attempt.")
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
        lastError = nil
    }

    /// Handles the successful result from the sign-in UI flow.
    private func completeSuccessfulSignIn(user: User) async {
        print("AuthService: Completing successful sign-in for user \(user.uid).")
        // Check if we need to perform account linking
        if let pendingCred = firebaseAuthenticator.pendingCredentialForLinking {
             print("AuthService: Post-SignIn - Attempting to link credential...")
             do {
                 try await performAccountLink(loggedInUser: user, pendingCredential: pendingCred)
                 // Success state set by performAccountLink or listener
             } catch {
                  print("AuthService Error: Post-SignIn - Linking failed: \(error)")
                  if let authError = error as? AuthError {
                       lastError = authError
                  } else {
                       lastError = .accountLinkingError(error.localizedDescription)
                  }
                  // Go back to signed out on linking failure after successful sign-in
                  state = .signedOut
                  firebaseAuthenticator.clearTemporaryCredentials() // Ensure clean state
                  emailForLinking = nil
             }
        } else {
            // Regular sign-in success or merge conflict resolution success.
            // The AuthState listener should handle setting the final .signedIn state.
            print("AuthService: Post-SignIn - Standard success or merge resolution completed. State update handled by listener.")
            // We clear the merge conflict credential IF it exists, linking cred handled above
            if firebaseAuthenticator.existingCredentialForMergeConflict != nil {
                firebaseAuthenticator.clearTemporaryCredentials()
                emailForLinking = nil
            }
            // Ensure the state reflects signedIn (listener might be delayed)
            if state != .signedIn(user) {
                print("AuthService: Post-SignIn - Forcing state update to signedIn.")
                state = .signedIn(user) // Force update if listener hasn't caught up
            }
        }
    }

    /// Handles specific AuthErrors from the sign-in flow that require state changes.
    private func handleSignInAuthError(_ error: AuthError) async {
         print("AuthService: Handling AuthError: \(error)")
        lastError = error // Publish the error

        switch error {
        case .accountLinkingRequired:
            // Ensure credential is still stored
            guard let pendingCred = firebaseAuthenticator.pendingCredentialForLinking,
                  let email = pendingCred.userInfo?.email else { // Extract email
                print("AuthService Error: Missing info for accountLinkingRequired state.")
                state = .signedOut
                firebaseAuthenticator.clearTemporaryCredentials()
                lastError = .missingLinkingInfo
                return
            }
            self.emailForLinking = email // Store email for the state
            do {
                let methods = try await Auth.auth().fetchSignInMethods(forEmail: email)
                print("AuthService: Setting state to .requiresAccountLinking for email \(email) with providers: \(methods)")
                state = .requiresAccountLinking(email: email, existingProviders: methods)
                // Keep temporary credential in firebaseAuthenticator
            } catch {
                 print("AuthService Error: Fetching sign-in methods failed: \(error)")
                 state = .signedOut // Fallback
                 firebaseAuthenticator.clearTemporaryCredentials()
                 emailForLinking = nil
                 lastError = .firebaseAuthError(error) // Publish fetch error
            }

        case .mergeConflictRequired:
            // Ensure credential is still stored
            guard firebaseAuthenticator.existingCredentialForMergeConflict != nil else {
                print("AuthService Error: Missing existing credential for merge conflict state.")
                state = .signedOut
                lastError = .missingLinkingInfo
                return
            }
            print("AuthService: Setting state to .requiresMergeConflictResolution.")
            state = .requiresMergeConflictResolution
            // Keep temporary credential in firebaseAuthenticator

        case .cancelled:
            print("AuthService: Handling cancelled sign-in.")
            // Reset state only if we weren't in a pending resolution state
            if state == .authenticating("Starting sign in...") || state == .signedOut || state == .requiresBiometrics {
                state = .signedOut
            } else {
                 print("AuthService: Cancellation occurred while in pending state (\(state)). Staying in state.")
                 // Stay in requiresLinking/Merge state for user to explicitly cancel via cancelPendingAction
            }

        default:
            // Handle other AuthKit-defined errors
            print("AuthService: Handling other AuthError: \(error.localizedDescription)")
            state = .signedOut // Default to signed out for most other errors
            firebaseAuthenticator.clearTemporaryCredentials()
            emailForLinking = nil
        }
    }

    /// Handles generic (non-AuthKit defined) errors from the sign-in flow.
    private func handleSignInGenericError(_ error: Error) {
        print("AuthService: Handling Generic Error during sign-in: \(error)")
        lastError = .firebaseAuthError(error) // Wrap generic errors
        state = .signedOut
        firebaseAuthenticator.clearTemporaryCredentials()
        emailForLinking = nil
    }

    /// Attempts to link the previously pending credential after the user has signed in
    /// with an existing provider.
    private func performAccountLink(loggedInUser: User, pendingCredential: AuthCredential) async throws {
         guard let firebaseUser = Auth.auth().currentUser, firebaseUser.uid == loggedInUser.uid else {
             print("AuthService Error: User mismatch during linking attempt.")
             throw AuthError.accountLinkingError("User mismatch during linking.")
         }
         state = .authenticating("Linking accounts...")
         lastError = nil

         do {
             _ = try await firebaseUser.link(with: pendingCredential)
             print("AuthService: Account successfully linked!")
             // State should be updated by listener to signedIn, but force it just in case
             state = .signedIn(User(firebaseUser: firebaseUser)) // Use refreshed user data
             firebaseAuthenticator.clearTemporaryCredentials()
             emailForLinking = nil
             lastError = nil
         } catch {
              print("AuthService Error: Linking process failed: \(error)")
              // Keep state as authenticating? Or revert? Reverting seems safer.
              // state = .signedOut // Let caller handle state reset
              firebaseAuthenticator.clearTemporaryCredentials()
              emailForLinking = nil
              // Throw a specific linking error
              throw AuthError.accountLinkingError("Linking failed: \(error.localizedDescription)")
         }
     }

    // MARK: - Internal State Management (Firebase Listener)

    private func handleAuthStateChange(firebaseUser: FirebaseAuth.User?) {
        DispatchQueue.main.async { [weak self] in // Ensure UI updates on main thread
            guard let self = self else { return }

            if let firebaseUser = firebaseUser {
                 print("AuthService Listener: User is PRESENT (\(firebaseUser.uid)). Current State: \(self.state)")
                // --- Scenario 1: User just signed in (or is already signed in) ---
                let newUser = User(firebaseUser: firebaseUser)

                // Avoid overriding if we are in a state requiring user action
                if self.state.isPendingResolution {
                     print("AuthService Listener: Ignoring listener update because state is pending resolution.")
                     return
                }

                // Avoid redundant updates if already correctly signed in
                if case .signedIn(let currentUser) = self.state, currentUser.uid == newUser.uid {
                     // If the user object itself changed (e.g., email verified), update it
                     if self.state != .signedIn(newUser) {
                          print("AuthService Listener: Updating signedIn user data.")
                          self.state = .signedIn(newUser)
                     } else {
                          // Check if biometrics became required (e.g., after backgrounding)
                          self.checkBiometricsRequirement(for: newUser)
                          print("AuthService Listener: State already correct (.signedIn). Biometric check performed.")
                     }
                     return
                }

                // If not currently signed in or user changed, check for biometrics
                 print("AuthService Listener: User present, checking biometrics requirement.")
                self.checkBiometricsRequirement(for: newUser)

            } else {
                // --- Scenario 2: User signed out ---
                 print("AuthService Listener: User is ABSENT. Current State: \(self.state)")
                if self.state != .signedOut {
                    print("AuthService Listener: Setting state to .signedOut.")
                    // Clear local data associated with a signed-in user
                    try? self.secureStorage.clearLastUserID()
                    self.firebaseAuthenticator.clearTemporaryCredentials()
                    self.emailForLinking = nil
                    self.lastError = nil // Clear errors on sign out
                    self.state = .signedOut
                } else {
                     print("AuthService Listener: State already correct (.signedOut).")
                }
            }
        }
    }

    /// Checks if the current user requires biometric authentication.
    private func checkBiometricsRequirement(for user: User) {
         // Don't prompt for biometrics for anonymous users
         guard !user.isAnonymous else {
             print("AuthService: Skipping biometrics check for anonymous user.")
             if state != .signedIn(user) { state = .signedIn(user) }
             return
         }

         let lastUserID = self.secureStorage.getLastUserID()
         print("AuthService: Checking biometrics. Last stored user ID: \(lastUserID ?? "None"), Current user ID: \(user.uid)")

         if lastUserID == user.uid && self.biometricAuthenticator.isBiometricsAvailable {
             print("AuthService: User matches last session, biometrics available. Setting state to .requiresBiometrics.")
             // Only transition if not already signed in (prevents loop after biometric success)
             if !(self.state == .signedIn(user)) {
                 self.state = .requiresBiometrics
             } else {
                  print("AuthService: Already signed in, skipping transition to requiresBiometrics.")
             }
         } else {
             print("AuthService: User doesn't match last session or biometrics unavailable. Setting state to .signedIn.")
             // Update state if not already correct
             if self.state != .signedIn(user) {
                 self.state = .signedIn(user)
             }
             // If sign in happened without biometrics prompt (e.g., first time, different user), update lastUserID
             if lastUserID != user.uid {
                 print("AuthService: Updating last stored user ID.")
                 try? self.secureStorage.saveLastUserID(user.uid)
             }
         }
     }
}