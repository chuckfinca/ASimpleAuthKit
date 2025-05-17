// swift-tools-version: 5.8
import PackageDescription

let package = Package(
    name: "ASimpleAuthKit",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "ASimpleAuthKit",
            targets: ["ASimpleAuthKit"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/firebase/firebase-ios-sdk.git",
            from: "10.0.0" // Or your current version e.g., 10.22.0
        ),
        .package( // Add GoogleSignIn
            url: "https://github.com/google/GoogleSignIn-iOS.git",
            from: "7.0.0" // Check for the latest version
        )
    ],
    targets: [
        .target(
            name: "ASimpleAuthKit",
            dependencies: [
                .product(name: "FirebaseAuth", package: "firebase-ios-sdk"),
                .product(name: "GoogleSignIn", package: "GoogleSignIn-iOS"),
                .product(name: "GoogleSignInSwift", package: "GoogleSignIn-iOS") // For Swift Concurrency support
            ]
        ),
        .testTarget(
            name: "ASimpleAuthKitTests",
            dependencies: [
                "ASimpleAuthKit",
                .product(name: "FirebaseAuth", package: "firebase-ios-sdk"),
            ],
            path: "Tests/ASimpleAuthKitTests",
            resources: [
                .copy("GoogleService-Info-Tests.plist")
            ]
        )
    ]
)
