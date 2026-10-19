// swift-tools-version: 6.0
import PackageDescription

// Shared code for the Flynn app and its Network Extensions: the Rust core
// (FlynnCore.xcframework, built by scripts/build-xcframework.sh), its
// generated Swift bindings, and the host implementations every target uses.
let package = Package(
    name: "FlynnKit",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "FlynnKit", targets: ["FlynnKit"]),
    ],
    targets: [
        .binaryTarget(name: "FlynnCore", path: "FlynnCore.xcframework"),
        .target(name: "FlynnKit", dependencies: ["FlynnCore"]),
        .testTarget(name: "FlynnKitTests", dependencies: ["FlynnKit"]),
    ]
)
