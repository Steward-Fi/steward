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
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "Steward",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(name: "StewardTests", dependencies: ["Steward"]),
    ]
)
