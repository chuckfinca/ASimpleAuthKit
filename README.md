# ASimpleAuthKit

[![Swift Version](https://img.shields.io/badge/Swift-5.8+-orange.svg)]()
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2016.0+-blue.svg)]()
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
<!-- Add other badges like build status, version -->

A simple Swift package to streamline Firebase Authentication integration (using FirebaseUI) in SwiftUI applications, handling common flows like sign-in, sign-out, state management, account linking, merge conflicts, biometrics, and secure keychain storage.

## Features

*   **FirebaseUI Integration:** Leverages `FirebaseAuthUI` for easy setup of common authentication providers (Email, Google, Apple, etc.).
*   **SwiftUI Friendly:** Provides an `@MainActor` `ObservableObject` (`AuthService`) that publishes the authentication state (`AuthState`) for easy use in SwiftUI views.
*   **State Management:** Defines clear states (`signedOut`, `authenticating`, `signedIn`, `requiresBiometrics`, `requiresAccountLinking`, `requiresMergeConflictResolution`).
*   **Account Linking & Merge Conflicts:** Handles the Firebase flows for linking accounts with the same email address and resolving merge conflicts.
*   **Biometric Authentication:** Optional support for authenticating returning users with Face ID / Touch ID (`.requiresBiometrics` state).
*   **Secure Keychain Storage:** Automatically stores the last signed-in user ID securely in the keychain to enable the biometric flow. Supports Keychain Access Groups for sharing credentials between apps.
*   **Error Handling:** Provides a specific `AuthError` enum for handling various authentication failures.
*   **Configurable:** Uses an `AuthConfig` struct to customize providers, URLs, keychain behavior, and Apple Sign-In persistence.

## Requirements

*   iOS 16.0+
*   Xcode 15.0+ (or as required by the Swift version)
*   Swift 5.9+

## Installation

Use the Swift Package Manager. Add the following dependency to your `Package.swift` file:

```swift
// In Package.swift dependencies:
dependencies: [
    .package(url: "https://github.com/chuckfinca/ASimpleAuthKit.git", from: "0.1.0") // Replace with your URL and desired version
]
```

Then, add `ASimpleAuthKit` as a dependency to your app target:

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

**ASimpleAuthKit assumes that *your application* handles the initial Firebase setup.**

1.  **Firebase Project:** You need a Firebase project set up for your application.
2.  **Add App to Project:** Add your iOS app to the Firebase project in the Firebase console.
3.  **Download `GoogleService-Info.plist`:** Download the configuration file from your Firebase project settings.
4.  **Add Plist to App Target:** Add the downloaded `GoogleService-Info.plist` file to your main application target in Xcode. **Ensure it's included in the target's "Copy Bundle Resources" build phase.**
5.  **Configure Firebase:** In your application's entry point (`AppDelegate` or SwiftUI `App` struct initializer), call `FirebaseApp.configure()` **before** initializing or using `AuthService` from this package.

    *   **AppDelegate:**
        ```swift
        import UIKit
        import FirebaseCore // Import FirebaseCore

        @main
        class AppDelegate: UIResponder, UIApplicationDelegate {
            func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
                FirebaseApp.configure() // Configure Firebase
                return true
            }
            // ... other app delegate methods
        }
        ```
    *   **SwiftUI App:**
        ```swift
        import SwiftUI
        import FirebaseCore // Import FirebaseCore

        @main
        struct YourApp: App {
            // Register app delegate for Firebase setup
            @UIApplicationDelegateAdaptor(AppDelegate.self) var delegate

            var body: some Scene {
                WindowGroup {
                    ContentView()
                }
            }
        }

        // Separate AppDelegate class for configuration
        class AppDelegate: NSObject, UIApplicationDelegate {
          func application(_ application: UIApplication,
                           didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey : Any]? = nil) -> Bool {
            FirebaseApp.configure()
            return true
          }
        }
        ```
        *(Using the AppDelegate approach is often the most reliable way for Firebase configuration with SwiftUI)*

6.  **Configure URL Schemes (If needed):** If using providers like Google Sign-In, follow the Firebase documentation to configure the necessary URL Schemes in your app's `Info.plist`.

## Basic Usage

```swift
import SwiftUI
import ASimpleAuthKit
import FirebaseAuthUI // Required for Auth Providers
import FirebaseCore   // Required for getting clientID if using Google

struct ContentView: View {
    // Create and observe the AuthService instance
    @StateObject var authService: AuthService

    init() {
        // 1. Configure Auth Providers (Replace with your desired providers)
        // Ensure FirebaseApp.configure() has run before accessing options
        let googleClientID = FirebaseApp.app()?.options.clientID

        var providers: [FUIAuthProvider] = [
            FUIEmailAuth(),
            // Add Google only if clientID is available
            // FUIGoogleAuth(clientID: googleClientID ?? ""), // Enable if using Google
            FUIOAuth.appleAuthProvider()
        ]

        // Example: Safely add Google Provider only if ClientID exists
        if let clientID = googleClientID, !clientID.isEmpty {
             providers.append(FUIGoogleAuth(clientID: clientID))
        } else {
            print("Warning: Firebase Client ID not found. Google Sign-In disabled.")
            // Handle the case where Google Sign-In cannot be enabled
        }


        // 2. Create AuthConfig
        let authConfig = AuthConfig(
            providers: providers,
            tosURL: URL(string: "https://your-terms-of-service.com"),       // Optional
            privacyPolicyURL: URL(string: "https://your-privacy-policy.com") // Optional
            // keychainAccessGroup: "YOUR_APP_GROUP_ID" // Optional: If sharing keychain
        )

        // 3. Initialize AuthService (FirebaseApp.configure() must have been called already)
        _authService = StateObject(wrappedValue: AuthService(config: authConfig))
    }

    // Helper to get the presenting view controller
    // You might use UIViewControllerRepresentable or other methods in a real app.
    // The included RootViewControllerFinder.swift has helpers for this.
    private func getPresentingViewController() -> UIViewController? {
        return findTopMostViewController() // Using helper from RootViewControllerFinder
    }

    var body: some View {
        VStack {
            switch authService.state {
            case .signedOut:
                Text("You are signed out.")
                Button("Sign In / Sign Up") {
                    Task {
                        if let presentingVC = getPresentingViewController() {
                            await authService.signIn(from: presentingVC)
                        } else {
                            print("Error: Could not find presenting view controller.")
                            // Handle error appropriately (e.g., show alert)
                        }
                    }
                }
            case .authenticating(let message):
                ProgressView(message ?? "Authenticating...")
            case .signedIn(let user):
                Text("Welcome, \(user.displayName ?? user.email ?? user.uid)!")
                Text("Provider: \(user.providerID ?? "N/A")")
                Button("Sign Out") {
                    authService.signOut()
                }
            case .requiresBiometrics:
                Text("Please authenticate with Biometrics.")
                // Access underlying BiometricAuthenticator properties safely if needed
                let biometryType = (authService as? AuthService)?.biometricAuthenticator.biometryTypeString ?? "Biometrics"
                Button("Use \(biometryType)") {
                    Task {
                        await authService.authenticateWithBiometrics() // Use default reason
                        // Or: await authService.authenticateWithBiometrics(reason: "Custom reason")
                    }
                }
                 Button("Sign In With Password Instead") { // Allow fallback
                    Task {
                        if let presentingVC = getPresentingViewController() {
                           await authService.signIn(from: presentingVC)
                        }
                    }
                 }
            case .requiresAccountLinking(let email, let providers):
                VStack {
                    Text("An account already exists with \(email).")
                        .padding(.bottom, 5)
                    Text("Sign in with one of your existing providers to link accounts:")
                        .font(.caption)
                        .multilineTextAlignment(.center)
                    Text(providers.joined(separator: ", "))
                        .font(.caption)
                        .bold()
                        .padding(.bottom)
                     Button("Continue Sign In to Link") { // Re-present UI to link
                         Task {
                             if let presentingVC = getPresentingViewController() {
                                await authService.signIn(from: presentingVC)
                             }
                         }
                     }
                     Button("Cancel") {
                         authService.cancelPendingAction()
                     }
                }
            case .requiresMergeConflictResolution:
                 VStack {
                     Text("Account Conflict")
                         .font(.headline)
                         .padding(.bottom)
                     Text("You previously signed in with a different method. Do you want to merge these accounts?")
                         .multilineTextAlignment(.center)
                         .padding(.bottom)
                     Button("Merge Accounts") {
                         Task {
                             await authService.proceedWithMergeConflictResolution()
                         }
                     }
                     Button("Cancel") {
                         authService.cancelPendingAction()
                     }
                 }
            }

            // Display Last Error (Optional)
            if let error = authService.lastError {
                Text("Error: \(error.localizedDescription)")
                    .foregroundColor(.red)
                    .padding(.top)
                    .font(.caption)
            }
        }
        .padding()
    }
}
```

## Lifecycle Management

It is crucial to manage the lifecycle of the `AuthService` instance, especially regarding its internal Firebase listener.

**Important:** When the `AuthService` instance is no longer needed (e.g., when the view using it disappears), you **must** call the `invalidate()` method. This ensures the Firebase authentication state listener is properly removed, preventing potential memory leaks or unexpected behavior.

**Example in SwiftUI:**

```swift
struct YourAuthenticatedView: View {
    @StateObject var authService: AuthService // Assuming initialized appropriately

    var body: some View {
        VStack {
            // ... your view content based on authService.state
        }
        .onDisappear {
            print("YourAuthenticatedView disappearing, invalidating AuthService.")
            authService.invalidate() // <-- Call invalidate here!
        }
    }
}

## Configuration Options (`AuthConfig`)

You configure `ASimpleAuthKit` by passing an `AuthConfig` struct when creating the `AuthService`.

*   `providers: [FUIAuthProvider]` (Required): An array of FirebaseUI authentication provider instances (e.g., `FUIEmailAuth()`, `FUIGoogleAuth(clientID: ...)`, `FUIOAuth.appleAuthProvider()`).
*   `tosURL: URL?` (Optional): A URL to your Terms of Service page, displayed by FirebaseUI.
*   `privacyPolicyURL: URL?` (Optional): A URL to your Privacy Policy page, displayed by FirebaseUI.
*   `keychainAccessGroup: String?` (Optional): If your app belongs to an App Group and you want to share the last logged-in user ID (for biometric auth) with other apps in the group, provide your App Group identifier here. Requires the "Keychain Sharing" capability to be enabled for your app target(s).
*   `appleUserPersister: ((_ appleUserID: String, _ firebaseUID: String) -> Void)?` (Optional): A callback invoked after a successful Sign in with Apple. Provides the stable Apple User ID and the corresponding Firebase UID. Use this to store your own mapping if needed for account management.

## API Overview

*   **`AuthService`**: The main `ObservableObject` class implementing `AuthServiceProtocol`, managing the authentication state and logic. Use `@StateObject` or `@EnvironmentObject` to manage its lifecycle.
*   **`AuthServiceProtocol`**: The protocol defining the public interface of `AuthService`.
*   **`AuthConfig`**: Struct used to configure `AuthService`.
*   **`AuthState`**: Enum representing the possible authentication states (`signedOut`, `authenticating`, `signedIn`, `requiresBiometrics`, `requiresAccountLinking`, `requiresMergeConflictResolution`).
*   **`AuthUser`**: Struct representing the signed-in user's basic information (`uid`, `email`, `displayName`, `isAnonymous`, `providerID`).
*   **`AuthError`**: Enum representing possible errors during authentication. Check `lastError` on `AuthService`.
*   **`RootViewControllerFinder.swift`**: Contains helper functions (`findTopMostViewController`) to find the currently visible view controller, often needed for presenting the FirebaseUI view controller.

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
