# EcliptixProtocol (Swift)

This Swift Package wraps the C API in a prebuilt XCFramework for iOS devices.

## Requirements
- iOS 17+
- Device builds (arm64)

## Usage (latest only)
The Swift package is at the repository root. Add it by tracking the default branch:

```swift
.package(url: "https://github.com/oleksandrmelnychenko/Ecliptix.Protection.Protocol", branch: "master")
```

Then import:
```swift
import EcliptixProtocol
```

The C API is re-exported as `EcliptixProtocolC`.

## Release workflow
- `build-ios.sh` builds `EcliptixProtocolC.xcframework.zip` and writes a checksum file.
- `update-package.sh <version> <checksum>` updates `/Package.swift` to point at the latest release asset.
- CI runs these steps on tag releases and keeps `Package.swift` aligned with the latest asset.
