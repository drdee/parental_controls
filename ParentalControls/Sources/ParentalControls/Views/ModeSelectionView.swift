import SwiftUI
import FamilySafetyCore

struct ModeSelectionView: View {
    @Bindable var state: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Family Safety Setup")
                    .font(.largeTitle.bold())
                Text("Filters web content and restricts changes on this Mac.")
                    .foregroundStyle(.secondary)
            }

            ForEach(RunMode.allCases) { mode in
                ModeCard(mode: mode, isSelected: state.mode == mode) {
                    state.mode = mode
                }
            }

            if state.mode == .advanced {
                Label {
                    Text("Advanced Mode changes user accounts and login settings. Use it only on a Mac you administer and can recover.")
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
                .font(.callout)
                .padding(12)
                .background(.orange.opacity(0.12), in: .rect(cornerRadius: 8))
            }

            Divider()

            // Undo lives on the main screen, visually separated from the setup
            // path: someone coming back to remove this should not have to walk
            // the wizard to find it.
            Button {
                state.stage = .revertConfirm
            } label: {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: "arrow.uturn.backward.circle.fill")
                        .foregroundStyle(.secondary)
                        .font(.title3)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Undo All Changes").font(.headline)
                        Text("Remove the profile, restore the hosts file, and re-enable what was turned off.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            .multilineTextAlignment(.leading)
                    }
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
                .padding(14)
                .overlay {
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(Color.secondary.opacity(0.3), style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
                }
            }
            .buttonStyle(.plain)

            VStack(alignment: .leading, spacing: 6) {
                Toggle(isOn: $state.dryRun) {
                    Text("Preview only — don't change anything")
                }
                .toggleStyle(.switch)
                Text(state.dryRun
                     ? "You'll walk through the whole setup and see exactly what would change, in plain language. Nothing on this Mac will be modified and no files will be saved."
                     : "Turn this on to walk through the setup and see what it would do, without changing anything.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(12)
            .background(state.dryRun ? Color.blue.opacity(0.1) : Color.secondary.opacity(0.06),
                        in: .rect(cornerRadius: 8))

            Spacer()

            HStack {
                if state.dryRun {
                    Label("Preview mode", systemImage: "eye")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(.blue)
                }
                Spacer()
                Button("Continue") {
                    state.stage = .configure
                    Task { await state.runPreflight() }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(24)
    }
}

private struct ModeCard: View {
    let mode: RunMode
    let isSelected: Bool
    let select: () -> Void

    var body: some View {
        Button(action: select) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: isSelected ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(isSelected ? Color.accentColor : .secondary)
                    .font(.title3)
                VStack(alignment: .leading, spacing: 4) {
                    Text(mode.title).font(.headline)
                    Text(mode.subtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
            }
            .padding(14)
            .background(isSelected ? Color.accentColor.opacity(0.08) : Color.clear,
                        in: .rect(cornerRadius: 10))
            .overlay {
                RoundedRectangle(cornerRadius: 10)
                    .stroke(isSelected ? Color.accentColor : Color.secondary.opacity(0.3))
            }
        }
        .buttonStyle(.plain)
    }
}
