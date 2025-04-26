// swift-tools-version: 6.1
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
        // Add both Firebase and FirebaseUI dependencies with proper versioning
        .package(
            url: "https://github.com/firebase/firebase-ios-sdk.git",
            from: "10.0.0"  
        ),
        .package(
            url: "https://github.com/firebase/FirebaseUI-iOS.git",
            from: "13.0.0"
        ),
    ],
    targets: [
        .target(
            name: "ASimpleAuthKit",
            dependencies: [
                .product(name: "FirebaseAuth", package: "firebase-ios-sdk"),
                .product(name: "FirebaseAuthUI", package: "FirebaseUI-iOS"),
                // Add other specific FirebaseUI components if needed
            ],
        ),
        .testTarget(
            name: "ASimpleAuthKitTests",
            dependencies: [
                "ASimpleAuthKit",
                .product(name: "FirebaseAuth", package: "firebase-ios-sdk"),
                .product(name: "FirebaseAuthUI", package: "FirebaseUI-iOS"),
            ]
        ),
    ]
)
