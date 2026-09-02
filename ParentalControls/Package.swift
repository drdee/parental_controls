// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ParentalControls",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "ParentalControls",
            path: "Sources/ParentalControls"
        )
    ]
)
