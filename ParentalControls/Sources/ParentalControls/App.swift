import SwiftUI
import FamilySafetyCore

@main
struct ParentalControlsApp: App {
    init() {
        // The build script asks the app to emit the installer's postinstall,
        // so the script and the review screen come from one source of truth.
        PackageScriptCommand.runIfRequested()
    }

    @State private var state = AppState()

    var body: some Scene {
        Window("Family Safety Setup", id: "main") {
            RootView(state: state)
                .frame(minWidth: 620, minHeight: 560)
        }
        .windowResizability(.contentMinSize)
    }
}

/// `--emit-package-scripts <family|advanced> <output-dir>`
///
/// A headless entry point used by `Scripts/build-pkg.sh`. Writes the
/// `postinstall` script and the configuration profile, then exits without
/// showing a window.
enum PackageScriptCommand {
    static func runIfRequested() {
        let arguments = CommandLine.arguments
        guard let flagIndex = arguments.firstIndex(of: "--emit-package-scripts") else { return }

        guard arguments.count > flagIndex + 2 else {
            FileHandle.standardError.write(Data("usage: --emit-package-scripts <family|advanced> <output-dir>\n".utf8))
            exit(2)
        }
        let modeName = arguments[flagIndex + 1]
        let outputPath = arguments[flagIndex + 2]

        guard let mode = RunMode(rawValue: modeName) else {
            FileHandle.standardError.write(Data("unknown mode '\(modeName)'; expected family or advanced\n".utf8))
            exit(2)
        }

        // Defaults matching the app's own, so a package built without the UI
        // behaves the same as one configured through it.
        let sites = BlockedSite.socialMedia + BlockedSite.aiChatbots
        let hardening = Hardening(runner: PrivilegedRunner(), blockedSites: sites)
        let generator = ProfileGenerator(blockedSites: sites, dnsBackend: .families)

        do {
            let builder = PackageBuilder(
                mode: mode,
                hardening: hardening,
                profileData: try generator.xmlData()
            )
            let directory = URL(fileURLWithPath: outputPath, isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

            let script = directory.appendingPathComponent("postinstall")
            try builder.postinstallScript().write(to: script, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)

            try builder.profileData.write(to: directory.appendingPathComponent("Family-Safety.mobileconfig"))

            print("wrote \(script.path)")
            print("wrote \(directory.appendingPathComponent("Family-Safety.mobileconfig").path)")
            exit(0)
        } catch {
            FileHandle.standardError.write(Data("failed: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}

struct RootView: View {
    @Bindable var state: AppState

    var body: some View {
        VStack(spacing: 0) {
            if let update = state.availableUpdate, !state.updateBannerDismissed {
                UpdateBanner(release: update) {
                    state.updateBannerDismissed = true
                }
            }
            stageView
        }
        .task {
            // Fire-and-forget: checkForUpdate swallows every failure, so a
            // missing network cannot delay or break the first screen.
            await state.checkForUpdate()
        }
    }

    @ViewBuilder
    private var stageView: some View {
        switch state.stage {
        case .chooseMode: ModeSelectionView(state: state)
        case .configure:  ConfigureView(state: state)
        case .review:     ReviewView(state: state)
        case .running:    RunningView(state: state)
        case .results:    ResultsView(state: state)
        case .revertConfirm: RevertConfirmView(state: state)
        case .reverting:     RevertingView()
        case .revertResults: RevertResultsView(state: state)
        }
    }
}

/// Tells the user a newer version exists and links to it.
///
/// Deliberately a banner rather than a sheet: an update notice must not stand
/// between someone and the task they opened the app to do.
struct UpdateBanner: View {
    let release: AvailableRelease
    let dismiss: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "arrow.down.circle")
                .foregroundStyle(.tint)
            Text("Version \(release.version.description) is available.")
                .font(.callout)
            Link("View release", destination: release.pageURL)
                .font(.callout)
            Spacer()
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark")
            }
            .buttonStyle(.plain)
            .help("Dismiss")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(.quaternary)
    }
}
