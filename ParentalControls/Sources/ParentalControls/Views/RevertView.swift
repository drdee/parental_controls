import SwiftUI
import FamilySafetyCore
import AppKit

/// Confirmation before undoing everything.
struct RevertConfirmView: View {
    @Bindable var state: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Undo All Changes").font(.largeTitle.bold())
                    Text("Return this Mac to how it was before Family Safety was set up.")
                        .foregroundStyle(.secondary)
                }

                detectedSection

                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(state.revertPlan, id: \.self) { item in
                            HStack(alignment: .firstTextBaseline, spacing: 7) {
                                Image(systemName: "arrow.uturn.backward.circle.fill")
                                    .foregroundStyle(.tint)
                                Text(item)
                                    .font(.callout)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                } header: {
                    SectionHeader("What will be undone", systemImage: "arrow.uturn.backward")
                }

                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(state.revertWillNotUndo, id: \.self) { item in
                            HStack(alignment: .firstTextBaseline, spacing: 7) {
                                Image(systemName: "circle.badge.xmark")
                                    .foregroundStyle(.secondary)
                                Text(item)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                } header: {
                    SectionHeader("What will be left alone", systemImage: "hand.raised.slash")
                }
            }
            .padding(24)
        }
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 0) {
                Divider()
                HStack {
                    Spacer()
                    Button("Cancel") { state.stage = .chooseMode }
                    Button("Undo Everything") {
                        state.stage = .reverting
                        Task { await state.revertEverything() }
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                }
                .padding(16)
            }
            .background(.bar)
        }
        .task { await state.detectExistingChanges() }
    }

    /// Says what is actually present, so "undo" on a clean Mac is honest
    /// rather than pretending to have done something.
    private var detectedSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 6) {
                if state.detectedChanges.isEmpty {
                    Label("Nothing from this tool was found on this Mac. Undoing is safe but will probably report nothing to do.",
                          systemImage: "checkmark.circle")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    ForEach(state.detectedChanges, id: \.self) { item in
                        Label(item, systemImage: "dot.circle.fill")
                            .font(.callout)
                    }
                }
            }
            .padding(12)
            .background(.quaternary.opacity(0.3), in: .rect(cornerRadius: 8))
        } header: {
            SectionHeader("Found on this Mac", systemImage: "magnifyingglass")
        }
    }
}

struct RevertingView: View {
    var body: some View {
        VStack(spacing: 16) {
            ProgressView().controlSize(.large)
            Text("Undoing changes…").font(.headline)
            Text("You may be asked for your administrator password.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }
}

struct RevertResultsView: View {
    @Bindable var state: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Undo Complete").font(.largeTitle.bold())
                    Text(summary).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                VStack(alignment: .leading, spacing: 9) {
                    ForEach(state.revertResults) { result in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Image(systemName: icon(for: result.outcome))
                                .foregroundStyle(color(for: result.outcome))
                            VStack(alignment: .leading, spacing: 1) {
                                Text(result.title).font(.callout.weight(.medium))
                                Text(result.detail)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }

                if !state.detectedChanges.isEmpty {
                    Label {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Still present").font(.callout.weight(.medium))
                            ForEach(state.detectedChanges, id: \.self) { item in
                                Text("• \(item)").font(.caption)
                            }
                            Text("Remove the profile in System Settings › General › Device Management to finish.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    }
                    .padding(12)
                    .background(.orange.opacity(0.12), in: .rect(cornerRadius: 8))
                }
            }
            .padding(24)
        }
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 0) {
                Divider()
                HStack {
                    Button("Open Device Management") {
                        if let url = URL(string: "x-apple.systempreferences:com.apple.Profiles-Settings.extension") {
                            NSWorkspace.shared.open(url)
                        }
                    }
                    Spacer()
                    Button("Done") { NSApplication.shared.terminate(nil) }
                        .buttonStyle(.borderedProminent)
                }
                .padding(16)
            }
            .background(.bar)
        }
    }

    private var summary: String {
        let reverted = state.revertResults.filter { $0.outcome == .reverted }.count
        let manual = state.revertResults.filter { $0.outcome == .manualStepRequired }.count
        if manual > 0 {
            return "\(reverted) undone. \(manual) needs one manual step — see below."
        }
        if reverted == 0 {
            return "Nothing from this tool was present, so nothing needed undoing."
        }
        return "\(reverted) changes undone. This Mac is back to how it was."
    }

    private func icon(for outcome: RevertResult.Outcome) -> String {
        switch outcome {
        case .reverted:           "checkmark.circle.fill"
        case .nothingToDo:        "minus.circle"
        case .manualStepRequired: "hand.raised.circle.fill"
        case .failed:             "xmark.circle.fill"
        }
    }

    private func color(for outcome: RevertResult.Outcome) -> Color {
        switch outcome {
        case .reverted:           .green
        case .nothingToDo:        .secondary
        case .manualStepRequired: .orange
        case .failed:             .red
        }
    }
}
