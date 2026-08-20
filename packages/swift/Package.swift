// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "Steward",
    platforms: [
        .iOS(.v13),
        .macOS(.v12),
    ],
    products: [
        .library(name: "Steward", targets: ["Steward"]),
    ],
    dependencies: [
        // CryptoKit is Apple-only; swift-crypto supplies the same API as the
        // `Crypto` module on Linux/Windows (CI runs `swift test` on ubuntu).
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "Steward",
            dependencies: [
                .product(
                    name: "Crypto",
                    package: "swift-crypto",
                    condition: .when(platforms: [.linux, .windows, .android])
                ),
            ]
        ),
        .testTarget(name: "StewardTests", dependencies: ["Steward"]),
    ]
)
