import PackageDescription

// Auto-updated to point at the latest release asset.
let binaryUrl = "https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol/releases/download/v1.1.1/EcliptixProtocolC.xcframework.zip"
let binaryChecksum = "a4bf803f76bbba66e09b2e0dd6d740b2815a8fbcbf73e7c61d052dc8e924649a"

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
