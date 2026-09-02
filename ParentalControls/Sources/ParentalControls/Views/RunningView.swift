import SwiftUI
import FamilySafetyCore

struct RunningView: View {
    @Bindable var state: AppState

    var body: some View {
        VStack(spacing: 18) {
            ProgressView()
                .controlSize(.large)
            Text("Applying changes…").font(.headline)

            if let progress = state.warpProgress {
                VStack(spacing: 6) {
                    ProgressView(value: progress)
                        .frame(width: 260)
                    Text("Downloading Cloudflare WARP — \(Int(progress * 100))%")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Text("You may be asked for your administrator password.")
                .font(.caption)
                .foregroundStyle(.secondary)

            if !state.stepResults.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(state.stepResults) { result in
                        HStack(spacing: 6) {
                            Image(systemName: result.succeeded ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(result.succeeded ? .green : .red)
                            Text(result.title).font(.caption)
                        }
                    }
                }
                .padding(.top, 6)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }
}
