import PackageDescription

// Auto-updated to point at the latest release asset.
let binaryUrl = "https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol/releases/download/v1.0.1/EcliptixProtocolC.xcframework.zip"
let binaryChecksum = "4d74dc95c174186913e82d5483bb12f7e581228e8ca8c76727b1a48cbe813eab"

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
