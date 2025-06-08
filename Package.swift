// swift-tools-version: 5.8
import PackageDescription

let package = Package(
    name: "ASimpleAuthKit",
    platforms: [
        .iOS(.v16),
        .macOS(.v10_15) 
    ],
    products: [
        .library(
            name: "ASimpleAuthKit",
            targets: ["ASimpleAuthKit"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/firebase/firebase-ios-sdk.git",
            from: "10.0.0"
        ),
        .package(
            url: "https://github.com/google/GoogleSignIn-iOS.git",
            from: "7.0.0"
        )
    ],
    targets: [
        .target(
            name: "ASimpleAuthKit",
            dependencies: [
                .product(name: "FirebaseAuth", package: "firebase-ios-sdk"),
                .product(name: "GoogleSignIn", package: "GoogleSignIn-iOS"),
                .product(name: "GoogleSignInSwift", package: "GoogleSignIn-iOS")
            ]
        ),
        .testTarget(
            name: "ASimpleAuthKitTests",
            dependencies: [
                "ASimpleAuthKit",
                .product(name: "FirebaseAuth", package: "firebase-ios-sdk")
            ],
            resources: [
                .copy("GoogleService-Info-Tests.plist")
            ]
        ),
    ]
)
