import SwiftUI

@main
struct ParentalControlsApp: App {
    @State private var state = AppState()

    var body: some Scene {
        Window("Family Safety Setup", id: "main") {
            RootView(state: state)
                .frame(minWidth: 620, minHeight: 560)
        }
        .windowResizability(.contentMinSize)
    }
}

struct RootView: View {
    @Bindable var state: AppState

    var body: some View {
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
