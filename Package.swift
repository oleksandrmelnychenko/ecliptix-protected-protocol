import PackageDescription

// Auto-updated to point at the latest release asset.
let binaryUrl = "https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol/releases/download/v1.1.0/EcliptixProtocolC.xcframework.zip"
let binaryChecksum = "2114eb7a0f98873da74bcfe5bbb287d87eff2b855af72a3c9e92f2301b8c4e54"

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
