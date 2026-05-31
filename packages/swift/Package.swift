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
    targets: [
        .target(name: "Steward"),
        .testTarget(name: "StewardTests", dependencies: ["Steward"]),
    ]
)

