import SwiftUI

/// The dry-run walkthrough: every change in plain language.
///
/// Structured around the three questions someone actually has — what changes,
/// what will I notice, and how do I undo it — rather than around the commands
/// that implement it.
struct ChangeWalkthrough: View {
    let changes: [ChangeDescription]
    @State private var expanded: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(changes) { change in
                ChangeCard(
                    change: change,
                    isExpanded: expanded.contains(change.id),
                    toggle: {
                        if expanded.contains(change.id) {
                            expanded.remove(change.id)
                        } else {
                            expanded.insert(change.id)
                        }
                    }
                )
            }

            if changes.contains(where: { $0.impact == .sensitive }) {
                Label {
                    Text("The highlighted change affects user accounts. Review it carefully before turning preview mode off.")
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
                .font(.caption)
                .padding(10)
                .background(.orange.opacity(0.12), in: .rect(cornerRadius: 8))
            }
        }
    }
}

private struct ChangeCard: View {
    let change: ChangeDescription
    let isExpanded: Bool
    let toggle: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button(action: toggle) {
                HStack(alignment: .firstTextBaseline, spacing: 9) {
                    Image(systemName: change.impact.symbolName)
                        .foregroundStyle(tint)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(change.title)
                            .font(.callout.weight(.semibold))
                            .fixedSize(horizontal: false, vertical: true)
                        Text(change.whatChanges)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 6)
                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .multilineTextAlignment(.leading)
            }
            .buttonStyle(.plain)

            if isExpanded {
                VStack(alignment: .leading, spacing: 7) {
                    detail("What you'll notice", change.whatTheyWillNotice, "eye")
                    detail("How to undo it", change.howToUndo, "arrow.uturn.backward")
                    if !change.affects.isEmpty {
                        detail("What it touches", change.affects.joined(separator: "\n"), "folder")
                    }
                }
                .padding(.leading, 26)
            }
        }
        .padding(12)
        .background(tint.opacity(0.07), in: .rect(cornerRadius: 9))
        .overlay {
            RoundedRectangle(cornerRadius: 9)
                .stroke(change.impact == .sensitive ? Color.orange.opacity(0.5) : Color.secondary.opacity(0.2))
        }
    }

    private var tint: Color {
        switch change.impact {
        case .additive:    .blue
        case .restrictive: .indigo
        case .sensitive:   .orange
        }
    }

    private func detail(_ label: String, _ text: String, _ symbol: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: symbol)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .frame(width: 13)
            VStack(alignment: .leading, spacing: 1) {
                Text(label)
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(text)
                    .font(.caption)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
