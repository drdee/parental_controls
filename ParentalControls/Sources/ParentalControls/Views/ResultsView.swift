import SwiftUI
import AppKit

struct ResultsView: View {
    @Bindable var state: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header

                if let error = state.runError {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .padding(12)
                        .background(.orange.opacity(0.12), in: .rect(cornerRadius: 8))
                }

                appliedSteps

                if let url = state.generatedProfileURL {
                    installProfileCard(url: url)
                }

                if !state.dryRun {
                    verificationSection
                }

                nextStepsSection
            }
            .padding(24)
        }
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 0) {
                Divider()
                HStack {
                    if state.dryRun {
                        Button("Apply These Changes For Real") {
                            state.dryRun = false
                            state.stepResults = []
                            state.stage = .review
                        }
                    } else {
                        Button("Verify Again") { Task { await state.runVerification() } }
                    }
                    Spacer()
                    Button("Done") { NSApplication.shared.terminate(nil) }
                        .buttonStyle(.borderedProminent)
                }
                .padding(16)
            }
            .background(.bar)
        }
        .task {
            if !state.dryRun { await state.runVerification() }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(state.dryRun ? "Preview Complete" : "Results").font(.largeTitle.bold())
            Text(state.dryRun
                 ? "Nothing was changed. This is what would have happened."
                 : "What was applied, and what still needs doing.")
                .foregroundStyle(.secondary)

            if state.dryRun {
                Label {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("No changes were made").font(.callout.weight(.medium))
                        Text("No profile was saved, no settings were altered, and no accounts were created. To apply these changes for real, go back and turn off preview mode.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } icon: {
                    Image(systemName: "checkmark.shield.fill").foregroundStyle(.blue)
                }
                .padding(12)
                .background(.blue.opacity(0.1), in: .rect(cornerRadius: 8))
            }
        }
    }

    private var appliedSteps: some View {
        Section {
            VStack(alignment: .leading, spacing: 7) {
                ForEach(state.stepResults) { result in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Image(systemName: result.succeeded ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundStyle(result.succeeded ? .green : .red)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(result.title).font(.callout.weight(.medium))
                            if !result.detail.isEmpty {
                                Text(result.detail)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }
            }
        } header: {
            SectionHeader(state.dryRun ? "Would be applied" : "Applied",
                          systemImage: state.dryRun ? "eye" : "checkmark.circle")
        }
    }

    /// The profile still has to be installed by hand; make that unmissable.
    private func installProfileCard(url: URL) -> some View {
        Section {
            VStack(alignment: .leading, spacing: 10) {
                Text("The configuration profile has been saved but not installed — macOS requires you to approve it yourself.")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)

                VStack(alignment: .leading, spacing: 3) {
                    stepLine(1, "Open the profile (button below).")
                    stepLine(2, "Go to System Settings › General › Device Management.")
                    stepLine(3, "Select “Family Safety” and click Install, then authenticate.")
                    stepLine(4, "Come back here and press Verify Again.")
                }

                HStack {
                    Button {
                        NSWorkspace.shared.open(url)
                    } label: {
                        Label("Open Profile", systemImage: "doc.badge.gearshape")
                    }
                    .buttonStyle(.borderedProminent)

                    Button {
                        NSWorkspace.shared.activateFileViewerSelecting([url])
                    } label: {
                        Label("Show in Finder", systemImage: "folder")
                    }
                }

                Text(url.path)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        } header: {
            SectionHeader("Install the profile", systemImage: "arrow.down.doc")
        }
    }

    private func stepLine(_ number: Int, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text("\(number).")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
            Text(text).font(.caption)
        }
    }

    /// Functional checks. Several profile keys fail silently on an
    /// unsupervised Mac, so "installed" is not the same as "working".
    private var verificationSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                if state.verifications.isEmpty {
                    Text("Not verified yet.").font(.caption).foregroundStyle(.secondary)
                }
                ForEach(state.verifications) { check in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Image(systemName: icon(for: check.outcome))
                            .foregroundStyle(color(for: check.outcome))
                        VStack(alignment: .leading, spacing: 1) {
                            Text(check.title).font(.callout.weight(.medium))
                            Text(check.detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            if let remedy = check.remedy {
                                Text(remedy)
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }
            }
        } header: {
            SectionHeader("Verification", systemImage: "checkmark.shield")
        }
    }

    private func icon(for outcome: Verification.Outcome) -> String {
        switch outcome {
        case .verified: "checkmark.circle.fill"
        case .notWorking: "xmark.circle.fill"
        case .inconclusive: "questionmark.circle.fill"
        }
    }

    private func color(for outcome: Verification.Outcome) -> Color {
        switch outcome {
        case .verified: .green
        case .notWorking: .red
        case .inconclusive: .secondary
        }
    }

    /// The parts no software can do, and the gap that no local control closes.
    private var nextStepsSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                bullet("Set up Family Sharing with a Child Apple Account, then turn on Screen Time from your own device. Enforced that way it cannot be switched off on this Mac.")
                bullet("In Screen Time › Content & Privacy, set App Store purchases to “Don’t Allow” so apps cannot be installed.")
                bullet("Set the home router's DNS to the same filtering resolver. That covers every device and survives a reinstall of this Mac.")
                bullet("A phone hotspot bypasses everything configured here. No setting on this Mac can prevent that — it needs Screen Time on the phone and an agreement.")
            }
        } header: {
            SectionHeader("Still to do", systemImage: "list.clipboard")
        }
    }

    private func bullet(_ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 7) {
            Text("•").foregroundStyle(.secondary)
            Text(text)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
