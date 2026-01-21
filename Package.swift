import PackageDescription

// Auto-updated to point at the latest release asset.
let binaryUrl = "https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol/releases/download/v1.0.0/EcliptixProtocolC.xcframework.zip"
let binaryChecksum = "224dcec5638e473a4c81d4b62d263cf4cee405a923a29e485f4742f31877a293"

let package = Package(
    name: "EcliptixProtocol",
    platforms: [
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "EcliptixProtocol",
            targets: ["EcliptixProtocol"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "EcliptixProtocolC",
            url: binaryUrl,
            checksum: binaryChecksum
        ),
        .target(
            name: "EcliptixProtocol",
            dependencies: ["EcliptixProtocolC"],
            path: "bindings/swift/Sources/EcliptixProtocol",
            linkerSettings: [
                .linkedLibrary("c++"),
                .linkedLibrary("z")
            ]
        )
    ]
)
