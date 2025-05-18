# ASimpleAuthKit: Streamlined Direct Firebase Authentication for SwiftUI

![alt text](https://img.shields.io/badge/Swift-5.8+-orange.svg)
![alt text](https://img.shields.io/badge/Platforms-iOS%2016.0+-blue.svg)
![alt text](https://img.shields.io/badge/License-MIT-blue.svg)

A simple Swift package to streamline direct Firebase Authentication SDK integration in SwiftUI applications, handling common flows like sign-in with various providers (Email, Google, Apple), sign-out, state management, account linking, biometrics, and secure keychain storage.

## Features

*   **Direct Firebase SDK Integration:** Uses `FirebaseAuth` directly for fine-grained control over authentication flows.
*   **Provider-Specific Logins:** Supports Email/Password, Google Sign-In (via GoogleSignIn SDK), and Sign in with Apple.
*   **Customizable UI:** Designed to work with your application's custom login and registration UI.
*   **SwiftUI Friendly:** Provides an `@MainActor ObservableObject` (`AuthService`) that publishes the authentication state (`AuthState`) for easy use in SwiftUI views.
*   **State Management:** Defines clear states (`.signedOut`, `.authenticating`, `.signedIn`, `.requiresBiometrics`, `.requiresAccountLinking`, `.requiresMergeConflictResolution`).
*   **Account Linking:** Handles the Firebase flows for linking accounts with the same email address when a user signs in with a new provider for an existing email.
*   **Biometric Authentication:** Optional support for authenticating returning users with Face ID / Touch ID (`.requiresBiometrics` state).
*   **Secure Keychain Storage:** Automatically stores the last signed-in user ID securely in the keychain to enable the biometric flow. Supports Keychain Access Groups for sharing credentials between apps.
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
            .product(name: "ASimpleAuthKit", package: "ASimpleAuthKit") // Or your package name if different
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
    @StateObject var authService: AuthService // Can be @EnvironmentObject if provided higher up
    @State private var email = ""
    @State private var password = ""
    @State private var displayName = "" // For sign-up

    // Helper to find the top-most view controller for presenting OS-level UIs (like Apple Sign-In)
    @MainActor
    private func getPresentingViewController() -> UIViewController? {
        // This relies on RootViewControllerFinder.swift being included in ASimpleAuthKit.
        // Ensure you have access to findTopMostViewController()
        return findTopMostViewController()
    }

    // If authService is not provided by @EnvironmentObject, initialize it:
    // init() {
    //     let authConfig = AuthConfig(
    //         tosURL: URL(string: "https://your-app.com/terms"),
    //         privacyPolicyURL: URL(string: "https://your-app.com/privacy")
    //         // keychainAccessGroup: "YOUR_TEAM_ID.com.your-bundle-prefix" // Optional for keychain sharing
    //     )
    //     _authService = StateObject(wrappedValue: AuthService(config: authConfig))
    // }
    
    var body: some View {
        NavigationView {
            VStack(spacing: 15) {
                switch authService.state {
                case .signedOut, .authenticating("") where authService.lastError == nil: // Treat initial empty authenticating message like signed out
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
                    
                    // TextField("Display Name (Optional)", text: $displayName).textFieldStyle(.roundedBorder) // For sign up
                    Button("Create Email Account") {
                        Task { await authService.createAccountWithEmail(email: email, password: password, displayName: displayName.isEmpty ? nil : displayName) }
                    }
                    
                    Divider()
                    
                    Button("Sign In with Google") {
                        Task {
                            guard let vc = getPresentingViewController() else {
                                print("Error: Could not find presenting VC for Google Sign-In.")
                                // Show an error to the user (e.g., update a @State var for an alert)
                                return
                            }
                            await authService.signInWithGoogle(presentingViewController: vc)
                        }
                    }
                    
                    Button("Sign In with Apple") {
                        Task {
                            guard let vc = getPresentingViewController() else {
                                print("Error: Could not find presenting VC for Apple Sign-In.")
                                // Show an error to the user
                                return
                            }
                            await authService.signInWithApple(presentingViewController: vc)
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
                        
                        // Re-present sign-in options. Example for Google:
                        if existingProviders.contains("google.com") || existingProviders.isEmpty { // Smart display
                            Button("Sign In with Google to Link") {
                                Task {
                                    if let vc = getPresentingViewController() {
                                        await authService.signInWithGoogle(presentingViewController: vc)
                                    }
                                }
                            }
                        }
                        // Add other relevant provider buttons (Apple, Email Sign-In for linking)

                        Button("Cancel Linking") {
                            authService.cancelPendingAction()
                        }
                        .padding(.top)
                    }
                    .padding()
                
                case .requiresMergeConflictResolution:
                    VStack {
                        Text("Account Conflict")
                            .font(.headline)
                        Text("There's an issue with linking accounts. Please try signing in with your primary method or contact support.")
                        Button("Cancel") { authService.cancelPendingAction() }
                    }
                }
                
                // Display lastError if it's present and not during an active authentication attempt
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
        // Example of providing authService to child views
        // .environmentObject(authService)
        .onDisappear {
            // If this YourAuthenticationScreen is the primary owner of authService,
            // and it's being permanently dismissed (not just covered by another sheet),
            // then invalidate. Otherwise, invalidate at a higher level (e.g., AppState deinit).
            // authService.invalidate()
        }
    }
    
    func readableProviderName(providerID: String) -> String {
        switch providerID {
        case "password": return "Email/Password"
        case "google.com": return "Google"
        case "apple.com": return "Apple"
        default: return providerID.capitalized
        }
    }
}
```

## Lifecycle Management

It is crucial to manage the lifecycle of the AuthService instance. When it's no longer needed (e.g., when the view owning it disappears or the app closes), you **must** call `authService.invalidate()`. This ensures the internal Firebase authentication state listener is properly removed, preventing potential memory leaks or unexpected behavior.

Example:

If AuthService is owned by a specific view that gets dismissed:

```swift
.onDisappear {
    authService.invalidate()
}
```

If AuthService is part of a global AppState object, `invalidate()` could be called in AppState's deinit or an equivalent lifecycle cleanup point.

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
  * **signOut()** (Synchronous, but state updates via listener are async)
  * **sendPasswordResetEmail(to:) async**
  * **authenticateWithBiometrics(reason:) async**
  * **cancelPendingAction()**: Reverts from states like .requiresAccountLinking to .signedOut.
  * **invalidate()**: Cleans up resources, primarily the Firebase auth state listener. Must be called.
* **AuthConfig**: Struct for initial configuration.
* **AuthState**: Enum representing different authentication states.
* **AuthUser**: Struct holding basic information about the authenticated user.
* **AuthError**: Enum for detailed error information.
* **RootViewControllerFinder.swift**: (Included in package) Helper findTopMostViewController() for presenting OS-level UIs from SwiftUI.
## Error Handling

Observe `authService.lastError` in your UI to display relevant error messages. The AuthError enum provides `.localizedDescription` and specific cases (e.g., `.wrongPassword`, `.emailAlreadyInUse`, `.accountLinkingRequired`) for robust error handling and guiding the user.

## Testing ASimpleAuthKit (For Package Contributors)

The package includes unit tests (ASimpleAuthKitTests) that utilize the Firebase Emulator Suite (specifically the Auth emulator) for certain internal functionality.

### Prerequisites for Running Package Tests:

* **Node.js & npm**: Required to install the Firebase CLI. ([Install Node.js](https://nodejs.org/))
* **Firebase CLI**: Install or update: `npm install -g firebase-tools`.
* **Login (Optional but Recommended)**: Run `firebase login` once to authenticate the CLI.

### Setup for Package Tests:

* **Emulator Config**: The firebase.json file (included in the package root) configures the Auth emulator (port 9099 by default).
* **Test Plist**: The Tests/ASimpleAuthKitTests/GoogleService-Info-Tests.plist file is included. It contains dummy placeholder values required to initialize the Firebase SDK for tests only. Do not use this file in a real application. It must not contain sensitive information. The Bundle ID in this test plist (oi.appsimple.ASimpleAuthKitTests) is used by the test setup.

### Running Package Tests:

1. **Start Emulator**: Navigate to the package's root directory in your terminal and run:

```bash
firebase emulators:start --only auth --project asimpleauthkit-test-project
```

(This uses a dummy project ID specified in test setup and the start command). Leave this terminal window running while you execute tests.

2. **Run Tests**:
   * **Xcode**: Open the package (Package.swift) in Xcode (File -> Open...) and run the tests for the ASimpleAuthKitTests target (Product -> Test or Cmd+U).
   * **Command Line**: In a new terminal window (while the emulator is running), navigate to the package root and run: `swift test`.

### Important Note on Testing Live Firebase SDK Calls in Package Tests:

Direct calls to `FirebaseAuth.Auth.auth()` methods that interact with the keychain (e.g., `signInAnonymously()`, `signIn(withEmail:password:)`) may fail or be unreliable within the Swift Package Manager's test environment. This is often due to Bundle ID mismatches and keychain entitlement issues inherent to how SPM test targets are built and run.

The majority of `AuthServiceTests` use a `MockFirebaseAuthenticator` to unit test AuthService's internal logic and state transitions robustly.

Tests that attempted to use live `Auth.auth()` calls against the emulator (e.g., for validating full linking flows or biometric re-authentication setup within the package tests) are currently skipped using `XCTSkip`. These specific scenarios are difficult to reliably test at the package level due to the aforementioned keychain limitations.

### Recommendation for Testing Full Integration:

It is highly recommended that consuming applications write their own integration tests for flows that involve ASimpleAuthKit interacting with a live (emulated) Firebase backend. These app-level tests will run in the app's correctly configured environment (correct bundle ID, entitlements, etc.), allowing for proper keychain access and providing more comprehensive end-to-end validation.

## Contributing

Contributions are welcome! Please feel free to open an issue on GitHub to discuss bugs or feature requests, or submit a pull request.

## License

This package is released under the MIT License. See the LICENSE file for details.
