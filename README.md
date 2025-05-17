# ASimpleAuthKit: Streamlined Direct Firebase Authentication for SwiftUI

![alt text](https://img.shields.io/badge/Swift-5.8+-orange.svg)

![alt text](https://img.shields.io/badge/Platforms-iOS%2016.0+-blue.svg)

![alt text](https://img.shields.io/badge/License-MIT-blue.svg)

A simple Swift package to streamline direct Firebase Authentication SDK integration in SwiftUI applications, handling common flows like sign-in with various providers (Email, Google, Apple), sign-out, state management, account linking, biometrics, and secure keychain storage.

## Features

* Direct Firebase SDK Integration: Uses FirebaseAuth directly for fine-grained control over authentication flows.
* Provider-Specific Logins: Supports Email/Password, Google Sign-In (via GoogleSignIn SDK), and Sign in with Apple.
* Customizable UI: Designed to work with your application's custom login and registration UI.
* SwiftUI Friendly: Provides an @MainActor ObservableObject (AuthService) that publishes the authentication state (AuthState) for easy use in SwiftUI views.
* State Management: Defines clear states (signedOut, authenticating, signedIn, requiresBiometrics, requiresAccountLinking, requiresMergeConflictResolution).
* Account Linking: Handles the Firebase flows for linking accounts with the same email address.
* Biometric Authentication: Optional support for authenticating returning users with Face ID / Touch ID (.requiresBiometrics state).
* Secure Keychain Storage: Automatically stores the last signed-in user ID securely in the keychain to enable the biometric flow. Supports Keychain Access Groups for sharing credentials between apps.
* Error Handling: Provides a specific AuthError enum for handling various authentication failures.
* Configurable: Uses an AuthConfig struct to customize URLs, keychain behavior, and Apple Sign-In persistence.

## Requirements

* iOS 16.0+
* Xcode 15.0+ (or as required by the Swift version)
* Swift 5.8+ (or as per package definition)
* Firebase SDK (FirebaseAuth - handled by this package)
* GoogleSignIn SDK (handled by this package if Google Sign-In is used by the app)
* Consuming app needs to configure its Firebase project and necessary platform settings (e.g., URL schemes for Google Sign-In, "Sign in with Apple" capability).

## Installation

Use the Swift Package Manager. Add the following dependency to your Package.swift file:

```swift
// In Package.swift dependencies:
dependencies: [
    .package(url: "https://github.com/YOUR_USERNAME/ASimpleAuthKit.git", from: "NEW_VERSION_HERE") // Replace with your URL and version
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

1. Firebase Project: You need a Firebase project.
2. Add App to Project: Add your iOS app to the Firebase project. Enable desired sign-in providers (Email/Password, Google, Apple) in the Firebase console (Authentication -> Sign-in method).
3. Download GoogleService-Info.plist: Download this from your Firebase project settings.
4. Add Plist to App Target: Add the downloaded GoogleService-Info.plist file to your main application target in Xcode. Ensure it's included in the target's "Copy Bundle Resources" build phase.
5. Configure Firebase in App: In your AppDelegate or SwiftUI App struct, call FirebaseApp.configure() before initializing AuthService.

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

6. URL Schemes (Google Sign-In):
   * If using Google Sign-In, open your Info.plist as source code and add the REVERSED_CLIENT_ID from your GoogleService-Info.plist as a URL Scheme.
   * Also, ensure your AppDelegate handles the Google Sign-In URL callback:

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

7. Sign in with Apple Capability:
   * In Xcode, select your app target, go to the "Signing & Capabilities" tab, and click the "+" button to add the "Sign in with Apple" capability.

## Basic Usage

Here's how you might use ASimpleAuthKit in a SwiftUI view:

```swift
import SwiftUI
import ASimpleAuthKit

struct YourAuthenticationScreen: View {
    @StateObject var authService: AuthService
    @State private var email = ""
    @State private var password = ""
    @State private var displayName = "" // For sign-up
    
    // Helper to find the top-most view controller for presenting OS-level UIs (like Apple Sign-In)
    // Ensure RootViewControllerFinder.swift (or similar logic) is part of your app or this package.
    @MainActor
    private func getPresentingViewController() -> UIViewController? {
        // This relies on RootViewControllerFinder.swift being included in ASimpleAuthKit's public API
        // or your app having a similar helper.
        return findTopMostViewController()
    }
    
    init() {
        let authConfig = AuthConfig(
            tosURL: URL(string: "https://your-app.com/terms"),
            privacyPolicyURL: URL(string: "https://your-app.com/privacy")
            // keychainAccessGroup: "YOUR_TEAM_ID.com.your-bundle-prefix" // Optional for keychain sharing
        )
        authService = StateObject(wrappedValue: AuthService(config: authConfig))
    }
    
    var body: some View {
        NavigationView { // Or whatever navigation structure your app uses
            VStack(spacing: 15) {
                switch authService.state {
                case .signedOut, .authenticating(""): // Treat initial empty authenticating message like signed out for UI
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
                    
                    // Example: Show display name field only if it's a create account flow
                    // TextField("Display Name (Optional)", text: $displayName).textFieldStyle(.roundedBorder)
                    Button("Create Email Account") {
                        Task { await authService.createAccountWithEmail(email: email, password: password, displayName: displayName.isEmpty ? nil : displayName) }
                    }
                    
                    Divider()
                    
                    Button("Sign In with Google") {
                        Task {
                            if let vc = getPresentingViewController() {
                                await authService.signInWithGoogle(presentingViewController: vc)
                            } else {
                                print("Error: Could not find presenting VC for Google Sign-In.")
                                // Show an error to the user
                            }
                        }
                    }
                    
                    Button("Sign In with Apple") {
                        Task {
                            if let vc = getPresentingViewController() {
                                await authService.signInWithApple(presentingViewController: vc)
                            } else {
                                print("Error: Could not find presenting VC for Apple Sign-In.")
                                // Show an error to the user
                            }
                        }
                    }
                    
                    Button("Forgot Password?") {
                        Task { await authService.sendPasswordResetEmail(to: email) }
                        // UI should show a message like "Password reset email sent if account exists."
                    }
                    .font(.caption)
                
                case .authenticating(let message):
                    ProgressView(message ?? "Processing...")
                
                case .signedIn(let user):
                    VStack {
                        Text("Welcome, \(user.displayName ?? user.email ?? user.uid)!")
                        Text("Provider: \(user.providerID ?? "N/A")")
                        Button("Sign Out") { authService.signOut() }
                    }
                
                case .requiresBiometrics:
                    VStack {
                        Text("Please authenticate using \(authService.biometryTypeString) to continue.")
                        Button("Use \(authService.biometryTypeString)") {
                            Task { await authService.authenticateWithBiometrics() }
                        }
                        Button("Sign In With Different Method") {
                            authService.cancelPendingAction() // This will revert to .signedOut
                        }
                    }
                
                case .requiresAccountLinking(let linkEmail, let existingProviders):
                    VStack(alignment: .center, spacing: 10) {
                        Text("Account Exists for \(linkEmail)")
                            .font(.headline)
                        if !existingProviders.isEmpty {
                            Text("You previously signed in with: \(existingProviders.map(readableProviderName).joined(separator: ", ")).")
                                .font(.footnote)
                        }
                        Text("Please sign in with one of your existing methods to link this new way of signing in.")
                            .font(.callout)
                            .multilineTextAlignment(.center)
                        
                        // Re-present sign-in options (e.g., Google, Apple, Email Sign-In button)
                        // For brevity, showing only Google as an example to re-trigger a sign-in for linking.
                        // Your app would show all relevant provider buttons here.
                        if existingProviders.contains("google.com") || existingProviders.isEmpty { // Smart display
                            Button("Sign In with Google to Link") {
                                Task {
                                    if let vc = getPresentingViewController() {
                                        await authService.signInWithGoogle(presentingViewController: vc)
                                    }
                                }
                            }
                        }
                        // Add other provider buttons similarly (Apple, Email Sign-In)
                        
                        Button("Cancel Linking") {
                            authService.cancelPendingAction()
                        }
                        .padding(.top)
                    }
                    .padding()
                
                case .requiresMergeConflictResolution: // Or the more specific .mergeConflictDetected
                    VStack {
                        Text("Account Conflict")
                            .font(.headline)
                        Text("There's an issue with linking accounts. Please try signing in with your primary method or contact support.")
                        Button("Cancel") { authService.cancelPendingAction() }
                    }
                
                // case .reauthenticationRequired: // Example if you add this state
                    // Text("Please sign in again to complete your previous action.")
                    // Show relevant sign-in buttons
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
            // If this YourAuthenticationScreen is the primary owner of authService,
            // and it's being permanently dismissed (not just covered by another sheet),
            // then invalidate. Otherwise, invalidate at a higher level (e.g., AppState deinit).
            // authService.invalidate()
        }
    }
    
    // Helper to make provider IDs more readable
    func readableProviderName(providerID: String) -> String {
        switch providerID {
        case "password": return "Email/Password"
        case "google.com": return "Google"
        case "apple.com": return "Apple"
        // Add other Firebase provider IDs as needed
        default: return providerID
        }
    }
}
```

## Lifecycle Management

It is crucial to manage the lifecycle of the AuthService instance. When it's no longer needed (e.g., when the view owning it disappears or the app closes), you must call authService.invalidate(). This ensures the internal Firebase authentication state listener is properly removed.

Example:

```swift
.onDisappear {
    authService.invalidate()
}
```
Or, if AuthService is part of a global AppState, invalidate() could be called in AppState's deinit or an equivalent lifecycle cleanup point.

## Configuration Options (AuthConfig)

ASimpleAuthKit is configured via the AuthConfig struct:

* tosURL: URL? (Optional): URL to your Terms of Service. Your UI can display this.
* privacyPolicyURL: URL? (Optional): URL to your Privacy Policy. Your UI can display this.
* keychainAccessGroup: String? (Optional): For sharing the last user ID (for biometrics) across apps in an App Group. Requires "Keychain Sharing" capability.
* appleUserPersister: ((_ appleUserID: String, _ firebaseUID: String) -> Void)? (Optional): Callback after Apple Sign-In providing the stable Apple User ID and Firebase UID for your own persistence needs.

## API Overview

* AuthService: The main ObservableObject class.
* AuthServiceProtocol: Defines AuthService's public interface:
* state: AuthState (Published)
* lastError: AuthError? (Published)
* biometryTypeString: String
* signInWithEmail(email:password:) async
* createAccountWithEmail(email:password:displayName:) async
* signInWithGoogle(presentingViewController:) async
* signInWithApple(presentingViewController:) async
* signOut() async (Note: signOut() itself is synchronous, but internal cleanup might be async, listener updates state)
* sendPasswordResetEmail(to:) async
* authenticateWithBiometrics(reason:) async
* cancelPendingAction()
* invalidate()
* AuthConfig: Configuration struct.
* AuthState: Enum for auth states.
* AuthUser: Struct for user info.
* AuthError: Enum for errors.
* RootViewControllerFinder.swift: (If included in package) Helpers like findTopMostViewController() for presenting OS-level UIs.

## Error Handling

Check authService.lastError to display relevant error messages to the user. The AuthError enum provides .localizedDescription and specific cases for robust error handling.

## Running Tests (For Contributors)

The package uses the **Firebase Emulator Suite** (specifically the Auth emulator) for testing internal functionality.

**Prerequisites:**

1.  **Node.js & npm:** Required to install the Firebase CLI. ([Install Node.js](https://nodejs.org/))
2.  **Firebase CLI:** Install globally: `npm install -g firebase-tools`.
3.  **Login (Optional):** Run `firebase login` once to authenticate the CLI.

**Setup:**

1.  **Emulator Config:** The necessary `firebase.json` file is included in the repository root to configure the Auth emulator (port `9099` by default).
2.  **Test Plist:** The `Tests/ASimpleAuthKitTests/GoogleService-Info-Tests.plist` file is included in the repository. It contains **dummy placeholder values** required to initialize the Firebase SDK *only* for tests. **Do not use this file in a real application.** It should not contain any sensitive information.

**Running:**

1.  **Start Emulator:** Navigate to the package's root directory in your terminal and run:
    ```bash
    firebase emulators:start --only auth --project asimpleauthkit-test-project
    ```
    *(This uses the dummy project ID specified in the test plist and start command).* Leave this terminal window running while you execute tests.
2.  **Run Tests:**
    *   **Xcode:** Open the package (`Package.swift`) in Xcode (File -> Open...) and run the tests for the `ASimpleAuthKitTests` target (Product -> Test or Cmd+U).
    *   **Command Line:** In a *new* terminal window (while the emulator is running in the other), navigate to the package root and run: `swift test`.

## Contributing

Contributions are welcome! Please feel free to open an issue on GitHub to discuss bugs or feature requests, or submit a pull request.

## License

This package is released under the MIT License. See [LICENSE](LICENSE) file for details.