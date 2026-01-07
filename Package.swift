import PackageDescription

// Auto-updated to point at the latest release asset.
let binaryUrl = "https://github.com/oleksandrmelnychenko/Ecliptix.Protected.Protocol/releases/download/v0.0.0/EcliptixProtocolC.xcframework.zip"
let binaryChecksum = "0000000000000000000000000000000000000000000000000000000000000000"

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
