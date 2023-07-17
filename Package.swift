// swift-tools-version: 5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "iroh",
    platforms: [
        .iOS(.v13),
        .macOS(.v11)
    ],
    products: [
        // Products define the executables and libraries a package produces,
        // making them visible to other packages.
        .library(
            name: "Iroh",
            targets: ["Iroh"]),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "Iroh",
            dependencies: ["LibIroh"],
            path: "swift/Sources/Iroh"),
        .testTarget(
            name: "IrohTests",
            dependencies: ["Iroh"],
            path: "swift/Tests/IrohTests"),
        .binaryTarget(
            name: "LibIroh",
            path: "target/LibIroh.xcframework"),
    ]
)
