# Biometric Authentication with ASimpleAuthKit

This guide explains how to implement biometric authentication (Face ID/Touch ID) in your app using ASimpleAuthKit's client-controlled approach.

## Overview

ASimpleAuthKit provides **biometric capabilities** but lets **your app control the policy**. This means:

- ✅ You decide when to offer biometric setup
- ✅ You control when biometric authentication is required  
- ✅ Library handles the technical implementation and security
- ✅ Per-device preferences with proper user ID validation

## Quick Start

### 1. Initialize BiometricController

```swift
import ASimpleAuthKit

@MainActor
class AppState: ObservableObject {
    let authService: any AuthServiceProtocol
    let biometricController: BiometricController
    
    init() {
        self.authService = AuthService(config: yourAuthConfig)
        self.biometricController = BiometricController.create(with: authService)
        
        Task {
            await setupBiometricFlow()
        }
    }
    
    private func setupBiometricFlow() async {
        await biometricController.loadPreferences()
        
        // Check if biometrics should be required on app launch
        let shouldRequire = await biometricController.shouldRequireBiometricsForCurrentSession()
        if shouldRequire {
            biometricController.requireBiometricAuthentication()
        }
    }
}
```

### 2. Handle Auth States in Your UI

```swift
struct ContentView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        switch appState.authService.state {
        case .signedOut:
            SignInView()
        case .requiresBiometrics:
            BiometricPromptView()
        case .signedIn(let user):
            MainAppView()
        case .authenticating(let message):
            LoadingView(message: message)
        // ... other states
        }
    }
}
```

### 3. Biometric Prompt View

```swift
struct BiometricPromptView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        VStack(spacing: 20) {
            Text("Use \(appState.biometricController.biometryTypeString)")
                .font(.title2)
            
            Button("Unlock") {
                Task {
                    await appState.authService.authenticateWithBiometrics(
                        reason: "Access your account"
                    )
                }
            }
            .buttonStyle(.prominent)
            
            Button("Sign In Another Way") {
                appState.authService.cancelPendingAction()
            }
            .buttonStyle(.secondary)
        }
    }
}
```

### 4. Offer Biometric Setup (After Sign-In)

```swift
struct PostSignInView: View {
    @EnvironmentObject var appState: AppState
    @State private var showBiometricSetup = false
    
    var body: some View {
        VStack {
            // Your main content
            
            // Offer biometric setup if available and not enabled
            if appState.biometricController.isBiometricsAvailable &&
               !appState.biometricController.isBiometricEnabled {
                BiometricSetupPrompt()
            }
        }
        .onAppear {
            // Decide when to show the setup prompt
            showBiometricSetup = shouldOfferBiometricSetup()
        }
    }
    
    private func shouldOfferBiometricSetup() -> Bool {
        // Your logic: after first sign-in? Every time? User preference?
        return true
    }
}

struct BiometricSetupPrompt: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        VStack(spacing: 16) {
            Text("Enable \(appState.biometricController.biometryTypeString)?")
                .font(.headline)
            
            Text("Sign in faster with \(appState.biometricController.biometryTypeString)")
                .font(.subheadline)
                .foregroundColor(.secondary)
            
            HStack(spacing: 12) {
                Button("Not Now") {
                    // Maybe remind later
                }
                .buttonStyle(.secondary)
                
                Button("Enable") {
                    Task {
                        await enableBiometrics()
                    }
                }
                .buttonStyle(.prominent)
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
    
    private func enableBiometrics() async {
        do {
            try await appState.biometricController.completeBiometricSetup()
            // Show success message
        } catch {
            // Show error message
            print("Failed to enable biometrics: \(error.localizedDescription)")
        }
    }
}
```

### 5. Settings Toggle

```swift
struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        Form {
            Section("Security") {
                if appState.biometricController.isBiometricsAvailable {
                    Toggle(
                        "Use \(appState.biometricController.biometryTypeString)",
                        isOn: Binding(
                            get: { appState.biometricController.isBiometricEnabled },
                            set: { enabled in
                                Task {
                                    if enabled {
                                        try? await appState.biometricController.completeBiometricSetup()
                                    } else {
                                        await appState.biometricController.disableBiometrics()
                                    }
                                }
                            }
                        )
                    )
                } else {
                    Text("\(appState.biometricController.biometryTypeString) not available")
                        .foregroundColor(.secondary)
                }
            }
        }
    }
}
```

## App Lifecycle Integration

### Handle App Launch

```swift
@main
struct YourApp: App {
    @StateObject private var appState = AppState()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .task {
                    await appState.handleAppLaunch()
                }
        }
    }
}
```

### Handle Foreground Transitions

```swift
struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.scenePhase) private var scenePhase
    
    var body: some View {
        // Your content
        .onChange(of: scenePhase) { newPhase in
            if newPhase == .active {
                Task {
                    await appState.handleAppWillEnterForeground()
                }
            }
        }
    }
}
```

## Key Methods Reference

### BiometricController

```swift
// Check capabilities
biometricController.isBiometricsAvailable: Bool
biometricController.biometryTypeString: String

// Preferences
await biometricController.loadPreferences()
biometricController.isBiometricEnabled: Bool

// Setup & Control
try await biometricController.enableBiometrics()
await biometricController.disableBiometrics()
try await biometricController.completeBiometricSetup()

// Session Management
await biometricController.shouldRequireBiometricsForCurrentSession() -> Bool
biometricController.requireBiometricAuthentication()
await biometricController.handleSuccessfulBiometricAuth()
```

### AuthService

```swift
// Manual biometric control
authService.requireBiometricAuthentication()
try await authService.testBiometricAuthentication()
await authService.authenticateWithBiometrics(reason: "Your reason")
authService.cancelPendingAction()
```

## Best Practices

### 1. User Experience
- Always make biometrics **optional**
- Provide clear explanations
- Easy to disable later
- Graceful fallbacks when biometrics fail

### 2. When to Offer Setup
```swift
// Good: After successful sign-in
func handleSuccessfulSignIn() {
    if shouldOfferBiometricSetup() {
        showBiometricSetupPrompt()
    }
}

// Good: In settings on-demand
// Bad: Automatically without asking
```

### 3. Security Considerations
- Biometrics supplement primary auth, don't replace it
- Handle biometric failures gracefully (3 attempts → logout)
- Validate user ID to prevent cross-user biometric access

### 4. Error Handling
```swift
do {
    try await biometricController.enableBiometrics()
} catch AuthError.biometricsNotAvailable {
    // Device doesn't support biometrics
} catch {
    // Other setup failures - show user-friendly message
}
```

## Migration from Automatic Biometrics

If you were using automatic biometric authentication:

1. **Remove automatic triggers** - successful sign-ins now go directly to `.signedIn`
2. **Add manual control** - use `BiometricController` to manage preferences
3. **Update UI** - handle `.requiresBiometrics` state explicitly
4. **Add setup flow** - offer biometric setup when appropriate

The new approach gives you complete control while maintaining security best practices.
