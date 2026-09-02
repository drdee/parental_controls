import SwiftUI
import FamilySafetyCore

/// Shows exactly what will change, including the literal commands.
///
/// Nothing should be applied that the user has not had the chance to read —
/// this is the last screen before the machine is modified.
struct ReviewView: View {
    @Bindable var state: AppState
    @State private var expandedCommands = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(state.dryRun ? "Preview" : "Review").font(.largeTitle.bold())
                    Text(state.dryRun
                         ? state.changePlan.summaryLine
                         : "Nothing has changed yet.")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                if state.dryRun {
                    Label {
                        Text("Preview mode is on. You can walk all the way through — nothing on this Mac will be changed and no files will be saved.")
                    } icon: {
                        Image(systemName: "eye.circle.fill").foregroundStyle(.blue)
                    }
                    .font(.callout)
                    .padding(12)
                    .background(.blue.opacity(0.1), in: .rect(cornerRadius: 8))
                }

                summary

                if state.dryRun {
                    ChangeWalkthrough(changes: state.changePlan.descriptions())
                } else {
                Section {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(state.plannedSteps) { step in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    Image(systemName: "arrow.right.circle.fill")
                                        .foregroundStyle(.tint)
                                    Text(step.title).font(.callout.weight(.medium))
                                    if step.isAdvancedOnly {
                                        Text("advanced")
                                            .font(.caption2)
                                            .padding(.horizontal, 5).padding(.vertical, 1)
                                            .background(.orange.opacity(0.2), in: .capsule)
                                    }
                                }
                                Text(step.explanation)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                                if expandedCommands {
                                    Text(step.command)
                                        .font(.caption2.monospaced())
                                        .textSelection(.enabled)
                                        .padding(8)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .background(.quaternary.opacity(0.4), in: .rect(cornerRadius: 6))
                                }
                            }
                        }
                        Toggle("Show exact commands", isOn: $expandedCommands)
                            .font(.caption)
                            .padding(.top, 4)
                    }
                } header: {
                    SectionHeader("System changes", systemImage: "gearshape")
                }
                }

                if !state.dryRun {
                    manualStepNotice
                }
            }
            .padding(24)
        }
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 0) {
                Divider()
                HStack {
                    Spacer()
                    Button("Back") { state.stage = .configure }
                    Button(state.dryRun ? "Run Preview" : "Apply") {
                        state.stage = .running
                        Task { await state.apply() }
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                }
                .padding(16)
            }
            .background(.bar)
        }
    }

    private var summary: some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                row("Mode", state.mode.title)
                row("DNS", state.dnsBackend.displayName)
                // Must reflect the presets, not just the editable list — that
                // list is empty by default now, and reporting "0 domains"
                // while blocking twelve would be actively misleading.
                row("Blocked sites", blockedSummary)
                if state.installWARP { row("WARP client", "Download and install") }
                if state.mode == .advanced, state.createAccount {
                    row("New account", "\(state.accountUsername) (standard, non-admin)")
                }
                if !state.dnsBackend.blocksSocialMediaByCategory {
                    Text("Cloudflare for Families has no social-media category, so social sites are blocked by the domain list and browser policy only.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.top, 2)
                }
            }
        } header: {
            SectionHeader("Summary", systemImage: "list.bullet.rectangle")
        }
    }

    /// Which categories are on, plus any manually added sites.
    private var blockedSummary: String {
        var parts: [String] = []
        if state.blockSocialMedia { parts.append("social media") }
        if state.blockAIChatbots { parts.append("AI chatbots") }
        if state.blockChatAndGaming { parts.append("chat and gaming") }
        if !state.blockedSites.isEmpty { parts.append("\(state.blockedSites.count) added") }

        let hostCount = state.effectiveBlockedSites.flatMap(\.allHosts).count
        if parts.isEmpty {
            return "None"
        }
        return parts.joined(separator: ", ") + " — \(hostCount) hostnames"
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: 110, alignment: .leading)
            Text(value)
            Spacer()
        }
        .font(.callout)
    }

    /// The profile cannot be installed programmatically, so set the
    /// expectation here rather than letting it look like a failure later.
    private var manualStepNotice: some View {
        Label {
            VStack(alignment: .leading, spacing: 3) {
                Text("One manual step is required").font(.callout.weight(.medium))
                Text("macOS no longer allows apps to install configuration profiles. This app writes the profile to your Downloads folder; you double-click it and approve it in System Settings › General › Device Management.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } icon: {
            Image(systemName: "hand.raised.circle.fill").foregroundStyle(.blue)
        }
        .padding(12)
        .background(.blue.opacity(0.1), in: .rect(cornerRadius: 8))
    }
}
