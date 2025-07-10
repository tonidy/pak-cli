// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SecureEnclaveSwift",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "SecureEnclaveSwift",
            type: .dynamic,
            targets: ["SecureEnclaveSwift"]
        ),
    ],
    targets: [
        .target(
            name: "SecureEnclaveSwift",
            dependencies: [],
            path: "Sources"
        ),
        .testTarget(
            name: "SecureEnclaveSwiftTests",
            dependencies: ["SecureEnclaveSwift"],
            path: "Tests"
        ),
    ]
) 