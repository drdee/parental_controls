// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ParentalControls",
    platforms: [.macOS(.v14)],
    targets: [
        // Logic lives in a library target so it can be tested; an executable
        // target cannot be imported. Tests use `@testable import`, so nothing
        // needs to be made public just to be testable.
        .target(
            name: "FamilySafetyCore",
            path: "Sources/FamilySafetyCore"
        ),
        .executableTarget(
            name: "ParentalControls",
            dependencies: ["FamilySafetyCore"],
            path: "Sources/ParentalControls"
        ),
        .testTarget(
            name: "FamilySafetyCoreTests",
            dependencies: ["FamilySafetyCore"],
            path: "Tests/FamilySafetyCoreTests"
        ),
        // The whole build, in Swift: `swift package build-family-safety`.
        // Writing to the package directory is required because the artifacts
        // land in build/.
        .plugin(
            name: "BuildTool",
            capability: .command(
                intent: .custom(
                    verb: "build-family-safety",
                    description: "Build the app bundle and installer package"
                ),
                permissions: [
                    .writeToPackageDirectory(reason: "writes the app bundle and installer to build/"),
                ]
            ),
            path: "Plugins/BuildTool"
        ),
    ]
)
