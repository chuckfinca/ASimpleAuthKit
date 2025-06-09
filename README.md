# ASimpleAuthKit: Streamlined Direct Firebase Authentication for SwiftUI

![Swift 5.8+](https://img.shields.io/badge/Swift-5.8+-orange.svg)
![Platforms iOS 16.0+](https://img.shields.io/badge/Platforms-iOS%2016.0+-blue.svg)
![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)

A simple Swift package to streamline direct Firebase Authentication SDK integration in SwiftUI applications, handling common flows like sign-in with various providers (Email, Google, Apple), sign-out, state management, account linking, biometrics, and secure keychain storage.

## Features

*   **Direct Firebase SDK Integration:** Uses `FirebaseAuth` directly for fine-grained control over authentication flows.
*   **Provider-Specific Logins:** Supports Email/Password, Google Sign-In (via GoogleSignIn SDK), and Sign in with Apple.
*   **Customizable UI:** Designed to work with your application's custom login and registration UI.
*   **SwiftUI Friendly:** Provides an `@MainActor ObservableObject` (`AuthService`) that publishes the authentication state (`AuthState`) for easy use in SwiftUI views.
*   **State Management:** Defines clear states (`.signedOut`, `.authenticating`, `.signedIn`, `.requiresBiometrics`, `.requiresAccountLinking`, `.requiresMergeConflictResolution`, `.emailInUseSuggestSignIn`).
*   **Account Linking:** Handles the Firebase flows for linking accounts with the same email address when a user signs in with a new provider for an existing email.
*   **Biometric Authentication:** Optional support for authenticating returning users with Face ID / Touch ID (`.requiresBiometrics` state).
*   **Secure Keychain Storage:** Automatically stores the last signed-in user ID securely in the keychain to enable the biometric flow. Supports Keychain Access Groups for sharing credentials between apps.
*   **Testable Architecture:** Core logic is decoupled from Firebase singletons, allowing for comprehensive and reliable unit testing.
*   **Error Handling:** Provides a specific `AuthError` enum for handling various authentication failures.
*   **Configurable:** Uses an `AuthConfig` struct to customize URLs, keychain behavior, and Apple Sign-In persistence.

## Requirements

*   iOS 16.0+
*   Xcode 15.0+ (or as required by the Swift version)
*   Swift 5.8+ (or as per package definition)
*   Firebase SDK (`FirebaseAuth` - handled by this package)
*   GoogleSignIn SDK (handled by this package if Google Sign-In is used by the app)
*   Consuming app needs to configure its Firebase project and necessary platform settings (e.g., URL schemes for Google Sign-In, "Sign in with Apple" capability).

## Installation

Use the Swift Package Manager. Add the following dependency to your `Package.swift` file:

```swift
// In Package.swift dependencies:
dependencies: [
    // Replace with your actual repository URL and desired version/branch
    .package(url: "https://github.com/YOUR_USERNAME/ASimpleAuthKit.git", from: "1.0.0")
]
```

Then, add ASimpleAuthKit as a dependency to your app target:

```swift
// In Package.swift targets:
targets: [
    .target(
        name: "YourAppTarget",
        dependencies: [
            .product(name: "ASimpleAuthKit", package: "ASimpleAuthKit")
        ]
    )
]
```

## Firebase Setup (For App Consumers)

ASimpleAuthKit assumes that your application handles the initial Firebase project setup and SDK configuration.

1. **Firebase Project:** Create a Firebase project if you haven't already.
2. **Add App to Project:** Add your iOS app to the Firebase project.
3. **Enable Sign-In Providers:** In the Firebase console (Authentication -> Sign-in method), enable the providers you intend to use (Email/Password, Google, Apple).
4. **Download GoogleService-Info.plist:** Download this configuration file from your Firebase project settings.
5. **Add Plist to App Target:** Add the downloaded GoogleService-Info.plist file to your main application target in Xcode. Ensure it's included in the target's "Copy Bundle Resources" build phase.
6. **Configure Firebase in App:** In your AppDelegate or SwiftUI App struct, call FirebaseApp.configure() before initializing AuthService.

```swift
// AppDelegate.swift
import UIKit
import FirebaseCore

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        FirebaseApp.configure()
        return true
    }
    // ...
}
```

Or in a SwiftUI App:

```swift
// YourApp.swift
import SwiftUI
import FirebaseCore

@main
struct YourApp: App {
    init() {
        FirebaseApp.configure()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
```

### URL Schemes (Google Sign-In):

If using Google Sign-In, you need to add a URL Scheme to your app:
1. Open your Info.plist.
2. Locate the REVERSED_CLIENT_ID value in your GoogleService-Info.plist.
3. In your app's Info.plist, add a new URL type, and paste the REVERSED_CLIENT_ID into the URL Schemes field.
4. Ensure your AppDelegate or SwiftUI App handles the Google Sign-In URL callback:

```swift
// AppDelegate.swift
import GoogleSignIn

func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
    var handled: Bool
    handled = GIDSignIn.sharedInstance.handle(url)
    if handled {
        return true
    }
    // Handle other custom URL types if needed
    return false
}
```

For SwiftUI App lifecycle:

```swift
// YourApp.swift
import SwiftUI
import GoogleSignIn

@main
struct YourApp: App {
    // ... (FirebaseApp.configure() in init) ...
    var body: some Scene {
        WindowGroup {
            ContentView()
                .onOpenURL { url in
                    GIDSignIn.sharedInstance.handle(url)
                }
        }
    }
}
```

### Sign in with Apple Capability:

In Xcode, select your app target, go to the "Signing & Capabilities" tab, and click the "+" button to add the "Sign in with Apple" capability.

## Basic Usage

Here's how you might use ASimpleAuthKit in a SwiftUI view:

```swift
import SwiftUI
import ASimpleAuthKit

struct YourAuthenticationScreen: View {
    @StateObject var authService: AuthService
    @State private var email = ""
    @State private var password = ""
    @State private var displayName = ""

    // Helper to find the top-most view controller for presenting OS-level UIs
    @MainActor
    private func getPresentingViewController() -> UIViewController? {
        // This relies on a helper like RootViewControllerFinder.swift
        return findTopMostViewController()
    }

    // Initialize AuthService if it's not provided by the environment
    init() {
        let authConfig = AuthConfig(
            tosURL: URL(string: "https://your-app.com/terms"),
            privacyPolicyURL: URL(string: "https://your-app.com/privacy")
        )
        _authService = StateObject(wrappedValue: AuthService(config: authConfig))
    }
    
    var body: some View {
        NavigationView {
            VStack(spacing: 15) {
                switch authService.state {
                case .signedOut, .authenticating(nil):
                    // Login Form UI
                    loginForm
                
                case .authenticating(let message):
                    ProgressView(message ?? "Processing...")
                
                case .signedIn(let user):
                    // Main authenticated view content
                    VStack {
                        Text("Welcome, \(user.displayName ?? user.email ?? user.uid)!")
                        Text("Provider: \(user.providerID ?? "N/A")")
                        Button("Sign Out") {
                            Task {
                                await authService.signOut()
                            }
                        }
                        .buttonStyle(.bordered)
                        .tint(.red)
                    }
                
                case .requiresBiometrics:
                    // Biometric prompt UI
                    biometricPrompt
                
                case .requiresAccountLinking(let linkEmail, let providers):
                    // Account linking prompt UI
                    linkingPrompt(email: linkEmail, providers: providers ?? [])

                case .emailInUseSuggestSignIn(let email):
                    // Suggest sign-in for existing email
                    emailInUsePrompt(email: email)
                
                case .requiresMergeConflictResolution:
                    // Merge conflict UI
                    Text("Account Conflict. Please contact support.")
                }
                
                if let error = authService.lastError, !authService.state.isAuthenticating {
                    Text("Error: \(error.localizedDescription)")
                        .foregroundColor(.red)
                        .font(.caption)
                        .padding(.top)
                }
            }
            .padding()
            .navigationTitle("Sign In / Sign Up")
        }
        .onDisappear {
            // Invalidate the service to clean up listeners
            authService.invalidate()
        }
    }
    
    // Extracted subview for the login form for better readability
    private var loginForm: some View {
        VStack(spacing: 15) {
            Text("Welcome").font(.largeTitle)
            
            TextField("Email", text: $email)
                .keyboardType(.emailAddress)
                .autocapitalization(.none)
                .textFieldStyle(.roundedBorder)
            
            SecureField("Password", text: $password)
                .textFieldStyle(.roundedBorder)
            
            Button("Sign In with Email") {
                Task { await authService.signInWithEmail(email: email, password: password) }
            }
            .buttonStyle(.borderedProminent)
            
            Button("Create Email Account") {
                Task { await authService.createAccountWithEmail(email: email, password: password) }
            }
            
            Divider()
            
            Button("Sign In with Google") {
                Task {
                    guard let vc = getPresentingViewController() else { return }
                    await authService.signInWithGoogle(presentingViewController: vc)
                }
            }
            
            Button("Sign In with Apple") {
                Task {
                    guard let vc = getPresentingViewController() else { return }
                    await authService.signInWithApple(presentingViewController: vc)
                }
            }

            Button("Forgot Password?") {
                Task { await authService.sendPasswordResetEmail(to: email) }
            }
            .font(.caption)
        }
    }
    
    // Extracted subview for biometric prompt
    private var biometricPrompt: some View {
        VStack(spacing: 20) {
            Text("Please authenticate using \(authService.biometryTypeString).")
            Button("Use \(authService.biometryTypeString)") {
                Task { await authService.authenticateWithBiometrics() }
            }
            .buttonStyle(.borderedProminent)
            Button("Sign In With A Different Method") {
                authService.resetAuthenticationState()
            }
        }
    }

    // Extracted subview for account linking
    private func linkingPrompt(email: String, providers: [String]) -> some View {
        VStack(alignment: .center, spacing: 10) {
            Text("Account Exists")
                .font(.headline)
            Text("An account already exists for \(email). Please sign in with one of your existing methods to link this new way of signing in.")
                .font(.callout)
                .multilineTextAlignment(.center)
            
            Button("Cancel") {
                authService.resetAuthenticationState()
            }
            .padding(.top)
        }
        .padding()
    }
    
    // Extracted subview for email in use
    private func emailInUsePrompt(email: String) -> some View {
        VStack(alignment: .center, spacing: 10) {
            Text("Email Already in Use")
                .font(.headline)
            Text("The email '\(email)' is already associated with an account. Please try signing in.")
                .font(.callout)
                .multilineTextAlignment(.center)
            
            Button("OK") {
                authService.resetAuthenticationState()
            }
            .padding(.top)
        }
        .padding()
    }
}
```

## Lifecycle Management

It is crucial to manage the lifecycle of the AuthService instance. When it's no longer needed (e.g., when the view owning it disappears or the app closes), you **must** call `authService.invalidate()`. This ensures the internal Firebase authentication state listener is properly removed, preventing potential memory leaks or unexpected behavior.

The deinit of AuthService also calls `invalidate()` as a safeguard, but explicit cleanup is best practice.

Example:

```swift
.onDisappear {
    authService.invalidate()
}
```

## Configuration Options (AuthConfig)

ASimpleAuthKit is configured via the AuthConfig struct passed to AuthService's initializer:

* **tosURL: URL? (Optional)**: URL to your Terms of Service.
* **privacyPolicyURL: URL? (Optional)**: URL to your Privacy Policy.
* **keychainAccessGroup: String? (Optional)**: For sharing the last user ID (for biometrics) across apps in an App Group. Requires the "Keychain Sharing" capability in your app target, configured with this group.
* **appleUserPersister: ((_ appleUserID: String, _ firebaseUID: String) -> Void)? (Optional)**: A callback invoked after a successful Apple Sign-In. It provides the stable Apple User ID and the corresponding Firebase UID, allowing your application to persist this mapping if needed (e.g., for server-side validation or account recovery).

## API Overview

* **AuthService: ObservableObject**: The main class for interacting with the authentication system.
  * **state: AuthState (Published)**: The current authentication state.
  * **lastError: AuthError? (Published)**: The last error that occurred.
  * **biometryTypeString: String**: A display string for the available biometry type ("Face ID", "Touch ID").
  * **signInWithEmail(email:password:) async**
  * **createAccountWithEmail(email:password:displayName:) async**
  * **signInWithGoogle(presentingViewController:) async**
  * **signInWithApple(presentingViewController:) async**
  * **signOut() async**: Signs the user out. Now an async method.
  * **sendPasswordResetEmail(to:) async**
  * **authenticateWithBiometrics(reason:) async**
  * **resetAuthenticationState()**: Reverts from states like .requiresAccountLinking to .signedOut.
  * **invalidate()**: Cleans up resources, primarily the Firebase auth state listener. Must be called.
* **AuthConfig**: Struct for initial configuration.
* **AuthState**: Enum representing different authentication states.
* **AuthUser**: Struct holding basic information about the authenticated user.
* **AuthError**: Enum for detailed error information.

## Error Handling

Observe `authService.lastError` in your UI to display relevant error messages. The AuthError enum provides `.localizedDescription` and specific cases (e.g., `.helpfulInvalidCredential`, `.emailAlreadyInUseDuringCreation`, `.accountLinkingRequired`) for robust error handling and guiding the user.

## Contributing

Contributions are welcome! Please feel free to open an issue on GitHub to discuss bugs or feature requests, or submit a pull request.

## License

This package is released under the MIT License. See the LICENSE file for details.
