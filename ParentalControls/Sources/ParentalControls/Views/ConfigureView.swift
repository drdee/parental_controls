import SwiftUI

struct ConfigureView: View {
    @Bindable var state: AppState
    @State private var newDomain = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                header

                PreflightSection(checks: state.preflightChecks)

                dnsSection

                safeSearchSection

                presetsSection

                blockedSitesSection

                if state.mode == .advanced {
                    accountSection
                }
            }
            .padding(24)
        }
        .safeAreaInset(edge: .bottom) { footer }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Configure").font(.largeTitle.bold())
            Text(state.mode.title).foregroundStyle(.secondary)
        }
    }

    // MARK: - DNS

    private var dnsSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 12) {
                Picker("Filtering provider", selection: $state.useZeroTrust) {
                    Text("Cloudflare for Families (1.1.1.3)").tag(false)
                    Text("Cloudflare Zero Trust Gateway").tag(true)
                }
                .pickerStyle(.radioGroup)

                if state.useZeroTrust {
                    VStack(alignment: .leading, spacing: 6) {
                        TextField("https://<id>.cloudflare-gateway.com/dns-query",
                                  text: $state.zeroTrustURL)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                        Text("Zero Trust adds a social-media content category, SafeSearch, custom lists, and query logs.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        // A mistyped gateway ID still answers DNS normally, so
                        // there is no way to validate it before installing.
                        Label("A mistyped endpoint still resolves DNS but applies no policy. Verification after install is what confirms filtering is live.",
                              systemImage: "info.circle")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.leading, 20)

                    Toggle("Also install the Cloudflare WARP client", isOn: $state.installWARP)
                        .padding(.leading, 20)
                    if state.installWARP {
                        Text("WARP enforces Zero Trust policy on the device itself and keeps filtering in place on any network, including a phone hotspot. ~150 MB download, signature verified before install.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .padding(.leading, 40)
                    }
                } else {
                    Text("Blocks malware and adult content. No account needed. It has no social-media category, so the list below does that work.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.leading, 20)
                }
            }
        } header: {
            SectionHeader("DNS filtering", systemImage: "network")
        }
    }

    // MARK: - Safe search

    private var safeSearchSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 10) {
                Toggle("Force SafeSearch on Google", isOn: $state.forceSafeSearch)
                Picker("YouTube restricted mode", selection: $state.youTubeLevel) {
                    ForEach(SafeSearch.YouTubeLevel.allCases) { level in
                        Text(level.title).tag(level)
                    }
                }
                .pickerStyle(.radioGroup)
                Text("These filter results *inside* Google and YouTube instead of blocking the sites, which is usually what you want for schoolwork. Strict YouTube also hides a lot of legitimate educational content, so Moderate is the better default.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Divider()

                Toggle("Turn off AirDrop", isOn: $state.restrictAirDrop)
                Text("Stops files arriving from strangers nearby. It also affects sharing schoolwork — worth agreeing with them rather than doing quietly.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } header: {
            SectionHeader("Safe search and sharing", systemImage: "magnifyingglass.circle")
        }
    }

    // MARK: - Presets

    private var presetsSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 14) {
                preset(
                    "Block social media",
                    isOn: $state.blockSocialMedia,
                    sites: BlockedSite.socialMedia,
                    detail: "TikTok, Instagram, Pinterest and Snapchat, including the mobile and link-shortener domains they redirect through."
                )

                preset(
                    "Block AI chatbots",
                    isOn: $state.blockAIChatbots,
                    sites: BlockedSite.aiChatbots,
                    detail: "ChatGPT, Claude, Gemini, Perplexity, Character.AI, Copilot, DeepSeek, Grok and Poe. Blocking only ChatGPT achieves very little now."
                )

                preset(
                    "Block chat and gaming sites",
                    isOn: $state.blockChatAndGaming,
                    sites: BlockedSite.chatAndGaming,
                    detail: "Discord, Reddit, Roblox, Twitch, Telegram, WhatsApp Web, X, Threads, Tumblr and BeReal. Off by default: Discord and Reddit have genuine school and club uses, and blocking them tends to produce a workaround rather than a change in behaviour."
                )
            }
        } header: {
            SectionHeader("Quick presets", systemImage: "square.stack.3d.up")
        }
    }

    /// One preset checkbox with its site count and rationale.
    private func preset(_ title: String,
                        isOn: Binding<Bool>,
                        sites: [BlockedSite],
                        detail: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Toggle(isOn: isOn) {
                HStack(spacing: 6) {
                    Text(title)
                    Text("\(sites.count) sites")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(.quaternary.opacity(0.5), in: .capsule)
                }
            }
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.leading, 20)
        }
    }

    // MARK: - Blocked sites

    private var blockedSitesSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                if state.blockedSites.isEmpty {
                    Text("Anything you add here is blocked in addition to the categories above.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(state.blockedSites) { site in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(site.domain).font(.body.monospaced())
                            if !site.extraHosts.isEmpty {
                                Text("+ \(site.extraHosts.count) related hosts")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                        Button {
                            state.blockedSites.removeAll { $0.domain == site.domain }
                        } label: {
                            Image(systemName: "minus.circle.fill").foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.vertical, 3)
                    Divider()
                }

                HStack {
                    TextField("example.com", text: $newDomain)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit(addDomain)
                    Button("Add", action: addDomain)
                        .disabled(cleanedDomain.isEmpty)
                }
            }
        } header: {
            SectionHeader("Additional sites", systemImage: "hand.raised")
        }
    }

    private var cleanedDomain: String {
        newDomain
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .replacingOccurrences(of: "www.", with: "")
            .split(separator: "/").first.map(String.init) ?? ""
    }

    private func addDomain() {
        let domain = cleanedDomain
        guard !domain.isEmpty, domain.contains("."),
              !state.blockedSites.contains(where: { $0.domain == domain }) else { return }
        state.blockedSites.append(BlockedSite(domain))
        newDomain = ""
    }

    // MARK: - Account

    private var accountSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 10) {
                Toggle("Create a standard (non-admin) account", isOn: $state.createAccount)
                Text("A standard account cannot change DNS, install apps, remove this profile, or enter Recovery. It is the control that makes everything else stick.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if state.createAccount {
                    Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
                        GridRow {
                            Text("Short name")
                            TextField("daughter", text: $state.accountUsername)
                                .textFieldStyle(.roundedBorder)
                        }
                        GridRow {
                            Text("Full name")
                            TextField("Optional", text: $state.accountFullName)
                                .textFieldStyle(.roundedBorder)
                        }
                    }
                    .padding(.leading, 20)

                    Label("You will be asked to set this account's password. Reboot and log in as this user before handing over the Mac — with FileVault on, an account without a Secure Token may not be able to unlock the disk.",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .padding(.leading, 20)
                }
            }
        } header: {
            SectionHeader("User account", systemImage: "person.crop.circle")
        }
    }

    // MARK: - Footer

    private var footer: some View {
        VStack(spacing: 0) {
            Divider()
            HStack {
                if let error = state.configurationError {
                    Label(error, systemImage: "exclamationmark.circle")
                        .font(.callout)
                        .foregroundStyle(.red)
                }
                Spacer()
                Button("Back") { state.stage = .chooseMode }
                Button("Review Changes") { state.stage = .review }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(state.configurationError != nil || state.preflightBlocks)
            }
            .padding(16)
        }
        .background(.bar)
    }
}

// MARK: - Shared pieces

struct SectionHeader: View {
    let title: String
    let systemImage: String

    init(_ title: String, systemImage: String) {
        self.title = title
        self.systemImage = systemImage
    }

    var body: some View {
        Label(title, systemImage: systemImage)
            .font(.headline)
            .padding(.bottom, 2)
    }
}

struct PreflightSection: View {
    let checks: [PreflightCheck]

    var body: some View {
        Section {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(checks) { check in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Image(systemName: icon(for: check.status))
                            .foregroundStyle(color(for: check.status))
                        VStack(alignment: .leading, spacing: 1) {
                            HStack(spacing: 6) {
                                Text(check.title).font(.callout.weight(.medium))
                                Text(check.detail)
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                            }
                            if let rationale = check.rationale, check.status != .pass {
                                Text(rationale)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }
            }
        } header: {
            SectionHeader("This Mac", systemImage: "checkmark.seal")
        }
    }

    private func icon(for status: PreflightCheck.Status) -> String {
        switch status {
        case .pass: "checkmark.circle.fill"
        case .warn: "exclamationmark.triangle.fill"
        case .fail: "xmark.circle.fill"
        }
    }

    private func color(for status: PreflightCheck.Status) -> Color {
        switch status {
        case .pass: .green
        case .warn: .orange
        case .fail: .red
        }
    }
}
