import AppKit
import ServiceManagement

// What Oarbank Node.app (deploy/macos/node/NodeApp.swift) and Oarbank Coordinator.app
// (deploy/macos/coordinator/Launcher.swift) share: the menu bar model of docs/design/node-enrollment.md, "Menu bar and
// tray". Each app is a menu bar extra with one setting, "Show <app> in the menu bar": on, its item is shown and the app
// opens at login; off, the app leaves the menu bar and quits, and opening it from Applications shows its window, where
// the setting turns it back on. The services the apps show (the node's launchd jobs, the coordinator's) have lifetimes
// of their own: neither app starts or stops them. One item per Mac: where Oarbank Coordinator is installed, its menu
// shows this Mac's node and Oarbank Node shows no item of its own.

enum Oarbank {
    static let nodeBundleBase = "dev.codonic.oarbank.node"
    static let coordinatorBundleBase = "dev.codonic.oarbank.coordinator"
    /// A test build carries a suffix on its identifier (`dev.codonic.oarbank.node.preview`): it pairs with the other
    /// app of the same suffix, never with the apps installed in /Applications.
    static let buildSuffix: String = {
        let id = Bundle.main.bundleIdentifier ?? ""
        for base in [nodeBundleBase, coordinatorBundleBase] where id.hasPrefix(base) { return String(id.dropFirst(base.count)) }
        return ""
    }()
    static var nodeBundleID: String { nodeBundleBase + buildSuffix }
    static var coordinatorBundleID: String { coordinatorBundleBase + buildSuffix }

    /// Where an app of this identifier is: one Launch Services knows (the packages install both apps in /Applications),
    /// else one running now (Launch Services leaves out apps in temporary folders).
    static func app(_ bundleID: String) -> URL? {
        NSWorkspace.shared.urlsForApplications(withBundleIdentifier: bundleID).first { FileManager.default.fileExists(atPath: $0.path) }
            ?? NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).compactMap(\.bundleURL).first
    }

    /// Opens the other app: launched with `arguments`, or, already running, reopened (each app shows its window then).
    static func open(_ bundleID: String, arguments: [String] = []) {
        guard let url = app(bundleID) else { return }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.arguments = arguments
        configuration.activates = true
        NSWorkspace.shared.openApplication(at: url, configuration: configuration) { _, _ in }
    }

    /// The node's managed-policy domain an MDM profile fills (docs/design/node-enrollment.md, "Managed policy keys").
    static let policyDomain = "dev.codonic.oarbank.agent" as CFString

    /// A managed-policy value (an MDM profile's forced value comes first in the search list).
    static func policy(_ key: String) -> Any? { CFPreferencesCopyAppValue(key as CFString, policyDomain) }

    /// A boolean policy, read as leniently as the agent reads it (rust/crates/oarbank-agent/src/policy.rs): a boolean,
    /// a number (0 is false) or the words true/false, yes/no, 1/0. Anything else is not set.
    static func policyBool(_ key: String) -> Bool? {
        switch policy(key) {
        case let number as NSNumber: return number.boolValue
        case let text as String:
            switch text.trimmingCharacters(in: .whitespaces).lowercased() {
            case "1", "true", "yes": return true
            case "0", "false", "no": return false
            default: return nil
            }
        default: return nil
        }
    }

    /// The organization a managed setting names: the status document's, else the policy's own.
    static func organization(_ status: NodeStatus? = nil) -> String? {
        let name = status?.managedBy ?? (policy("ManagedByOrganizationName") as? String)?.trimmingCharacters(in: .whitespaces)
        return name?.isEmpty == false ? name : nil
    }
}

/// The node's state from its status document: the system service's when one is set up, else this account's.
struct NodeStatus {
    var state = "unjoined"
    var coordinatorHost: String?
    var name: String?
    var userCode: String?
    var managedBy: String?
    var errorMessage: String?
    var errorCode: String?
    var exists = false

    static let paths = [
        "/Library/Application Support/Oarbank/status/node.json",
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Oarbank/status/node.json").path,
    ]

    static func read() -> NodeStatus {
        var status = NodeStatus()
        guard let path = paths.first(where: { FileManager.default.fileExists(atPath: $0) }),
              let data = FileManager.default.contents(atPath: path),
              let doc = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return status }
        status.exists = true
        status.state = doc["state"] as? String ?? "unjoined"
        if let url = doc["coordinator"] as? String { status.coordinatorHost = URLComponents(string: url)?.host ?? url }
        status.name = doc["name"] as? String
        status.userCode = doc["user_code"] as? String
        status.managedBy = doc["managed_by"] as? String
        if let error = doc["error"] as? [String: Any] {
            status.errorMessage = error["message"] as? String
            status.errorCode = error["code"] as? String
        }
        return status
    }

    /// Joined, or on the way (the join window then shows its progress and status rather than the code field).
    var hasJoinedOrIsJoining: Bool { !["unjoined", "error"].contains(state) }

    var summary: String {
        let host = coordinatorHost ?? "the coordinator"
        switch state {
        case "unjoined": return "Not joined"
        case "checking": return "Checking the coordinator…"
        case "joining": return "Joining \(host)…"
        case "pending": return "Waiting for approval"
        case "joined", "connected": return "Connected to \(host)"
        case "offline": return "Offline: cannot reach \(host)"
        case "error":
            let message = errorMessage ?? errorCode ?? "unknown error"
            return "Joining failed: \(message)"
        default: return "Status unavailable"
        }
    }

    /// A second line with what the person may need next: the approval code the owner enters, or the node's name.
    var detail: String? {
        switch state {
        case "pending": return userCode.map { "Approval code \($0)" }
        case "joined", "connected", "offline": return name.map { "This Mac: \($0)" }
        default: return nil
        }
    }

    /// AllowUserJoin false hides Join (the join window hides Leave); Status stays, it changes nothing.
    static var joinAllowed: Bool { Oarbank.policy("AllowUserJoin") as? Bool != false }
}

// ---------------------------------------------------------------- this Mac's node, as both apps show it

/// The node's service: the system LaunchDaemon (`oarbank-node join`'s default as root), else the account's LaunchAgent.
let systemServicePlist = "/Library/LaunchDaemons/dev.codonic.oarbank.agent.plist"
let personalServicePlist = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/dev.codonic.oarbank.agent.plist").path
/// Every launchd job of the node's. Their AssociatedBundleIdentifiers name this app, so System Settings, Login Items,
/// Allow in the Background lists them together as Oarbank Node: switched off there, launchd starts none of them.
let nodeJobPlists = [systemServicePlist, personalServicePlist, "/Library/LaunchAgents/dev.codonic.oarbank.agent.session.plist",
                     "/Library/LaunchDaemons/dev.codonic.oarbank.agent.policy.plist", "/Library/LaunchDaemons/dev.codonic.oarbank.agent.helper.plist"]

/// What the node's service is, in plain words.
func serviceDescription() -> String {
    if FileManager.default.fileExists(atPath: systemServicePlist) {
        return "Running as a system service — starts with the Mac, before anyone signs in, and keeps running when this app quits."
    }
    if FileManager.default.fileExists(atPath: personalServicePlist) {
        return "Running as a background service for your account — starts when you sign in, and keeps running when this app quits."
    }
    return "The node's service is not set up on this Mac. Install the Oarbank node package again."
}

let switchedOffMessage = "The node is turned off in Login Items → Allow in the Background. Turn Oarbank Node back on there."

/// The app's one setting, "Show <app> in the menu bar". On means the app's login item is registered
/// (`SMAppService.mainApp`): macOS is the source of truth, so removing the app from System Settings, Login Items, Open
/// at Login turns the setting off too. The first launch turns it on (an attended install opens the app). `managed`
/// (the node's `ShowStatusIcon` policy) decides instead when set, and the login item follows it.
final class MenuBarSetting {
    private let firstLaunchKey = "MenuBarSettingInitialized"
    private let managedValue: () -> Bool?
    init(managed: @escaping () -> Bool? = { nil }) { managedValue = managed }

    var managed: Bool? { managedValue() }
    var loginItem: SMAppService.Status { SMAppService.mainApp.status }
    var registered: Bool { loginItem == .enabled || loginItem == .requiresApproval }
    var isOn: Bool { managed ?? registered }
    /// macOS keeps the login item until someone approves it in Login Items: shown, but not opened at login.
    var needsApproval: Bool { loginItem == .requiresApproval }

    /// Turns the login item on or off; a no-op when it already is.
    func set(_ on: Bool) throws {
        if on && !registered { try SMAppService.mainApp.register() }
        if !on && registered { try SMAppService.mainApp.unregister() }
    }

    /// At launch: the first one turns the setting on, and managed policy has the login item follow it.
    func launched(allowFirstLaunch: Bool = true) {
        let defaults = UserDefaults.standard
        if defaults.object(forKey: firstLaunchKey) == nil {
            defaults.set(true, forKey: firstLaunchKey)
            if allowFirstLaunch && managed == nil { try? set(true) }
        }
        if let managed { try? set(managed) }
    }
}

/// launchd jobs that System Settings, Login Items, Allow in the Background has switched off: launchd then never starts
/// them. A job counts only when its property list is on this Mac.
func switchedOffInLoginItems(_ plists: [String]) -> Bool {
    plists.contains { path in
        FileManager.default.fileExists(atPath: path) && SMAppService.statusForLegacyPlist(at: URL(fileURLWithPath: path)) == .requiresApproval
    }
}

/// The menu bar glyph: `<name>.png` and `<name>@2x.png` in the app's resources (deploy/icons, rendered by
/// scripts/render-menu-bar-icons.swift), a template image so macOS tints it for the menu bar's appearance.
func menuBarGlyph(_ name: String) -> NSImage? {
    guard let image = Bundle.main.image(forResource: name) else { return nil }
    image.size = NSSize(width: 18, height: 18)
    image.isTemplate = true
    return image
}

// ---------------------------------------------------------------- the window's building blocks (System Settings' look)

func sectionTitle(_ text: String) -> NSTextField {
    let label = NSTextField(labelWithString: text)
    label.font = .systemFont(ofSize: NSFont.systemFontSize, weight: .semibold)
    label.setAccessibilityRole(.staticText)
    return label
}

/// The settings window's content width, and a group's rows inside it (System Settings' proportions).
let windowContentWidth: CGFloat = 440
let groupRowWidth: CGFloat = windowContentWidth - 28

func bodyLabel(_ text: String = "", secondary: Bool = false) -> NSTextField {
    let label = NSTextField(wrappingLabelWithString: text)
    label.font = .systemFont(ofSize: secondary ? NSFont.smallSystemFontSize : NSFont.systemFontSize)
    if secondary { label.textColor = .secondaryLabelColor }
    label.preferredMaxLayoutWidth = groupRowWidth
    label.widthAnchor.constraint(equalToConstant: groupRowWidth).isActive = true
    return label
}

/// A rounded group like System Settings' sections: its rows stacked, full width. Drawn rather than layered, so its
/// system colours follow the appearance (light, dark, increased contrast).
final class GroupView: NSView {
    override func draw(_ dirtyRect: NSRect) {
        let path = NSBezierPath(roundedRect: bounds.insetBy(dx: 0.5, dy: 0.5), xRadius: 8, yRadius: 8)
        NSColor.quaternarySystemFill.setFill(); path.fill()
        NSColor.separatorColor.setStroke(); path.lineWidth = 1; path.stroke()
    }
}

func group(_ rows: [NSView]) -> NSView {
    let box = GroupView()
    let stack = NSStackView(views: rows)
    stack.orientation = .vertical
    stack.alignment = .leading
    stack.spacing = 8
    stack.edgeInsets = NSEdgeInsets(top: 12, left: 14, bottom: 12, right: 14)
    stack.translatesAutoresizingMaskIntoConstraints = false
    box.addSubview(stack)
    NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: box.leadingAnchor), stack.trailingAnchor.constraint(equalTo: box.trailingAnchor),
                                 stack.topAnchor.constraint(equalTo: box.topAnchor), stack.bottomAnchor.constraint(equalTo: box.bottomAnchor),
                                 box.widthAnchor.constraint(equalToConstant: windowContentWidth)])
    return box
}

/// A row of buttons, left-aligned.
func buttonRow(_ buttons: [NSButton]) -> NSStackView {
    let row = NSStackView(views: buttons)
    row.orientation = .horizontal
    row.spacing = 8
    return row
}

/// The settings window: section titles and their groups, top to bottom, sized to what is visible.
func settingsWindow(title: String, sections: [(String, NSView)], delegate: NSWindowDelegate) -> NSWindow {
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: windowContentWidth + 40, height: 300),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
    window.title = title
    window.isReleasedWhenClosed = false
    window.delegate = delegate
    var views: [NSView] = []
    for (heading, content) in sections { views += [sectionTitle(heading), content] }
    let stack = NSStackView(views: views)
    stack.orientation = .vertical
    stack.alignment = .leading
    stack.spacing = 8
    for index in stride(from: 2, to: views.count, by: 2) { stack.setCustomSpacing(20, after: views[index - 1]) }
    stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
    stack.translatesAutoresizingMaskIntoConstraints = false
    let content = NSView()
    content.addSubview(stack)
    NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: content.leadingAnchor), stack.trailingAnchor.constraint(equalTo: content.trailingAnchor),
                                 stack.topAnchor.constraint(equalTo: content.topAnchor), stack.bottomAnchor.constraint(equalTo: content.bottomAnchor)])
    window.contentView = content
    return window
}

/// Resizes the window to its content (rows come and go with the node's state), keeping its top edge in place.
func fitWindow(_ window: NSWindow?) {
    guard let window, let content = window.contentView else { return }
    content.layoutSubtreeIfNeeded()
    let size = content.fittingSize
    var frame = window.frameRect(forContentRect: NSRect(origin: .zero, size: size))
    frame.origin = NSPoint(x: window.frame.minX, y: window.frame.maxY - frame.height)
    window.setFrame(frame, display: true)
}

/// An informative alert; returns whether the person chose the first button.
@discardableResult
func ask(_ title: String, _ detail: String, buttons: [String] = ["OK"]) -> Bool {
    NSApp.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.messageText = title
    alert.informativeText = detail
    for button in buttons { alert.addButton(withTitle: button) }
    return alert.runModal() == .alertFirstButtonReturn
}
