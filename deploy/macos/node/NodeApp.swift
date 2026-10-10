import AppKit
import ServiceManagement

// Oarbank Node: the node's menu bar front end (docs/design/node-enrollment.md, "Join window: files and launch
// contract"). It shows the status document the agent writes and runs the join window for joining and for status; it
// never joins, holds a code or talks to the coordinator itself. The node's service has a lifetime of its own: quitting
// this app leaves it running.
//
// Launch contract: `--join` opens the join window at once (the pkg's postinstall after a double-click install); an
// `oarbank://join?code=…` link (CFBundleURLTypes) runs it with `--link`, which shows the coordinator and asks before
// anything joins; reopening the app (Finder, `open -a` while it runs) opens the join window too.

let installRoot = "/Library/Oarbank"
let runtimePython = "\(installRoot)/bin/runtime/bin/python3"
let joinWindow = "\(installRoot)/share/join/join-window.py"
let launcher = "\(installRoot)/bin/oarbank-launcher"
// the managed-policy domain an MDM profile fills (docs/design/node-enrollment.md, "Managed policy keys")
let policyDomain = "dev.codonic.oarbank.agent" as CFString

/// The node's state from its status document: the system service's when one is set up, else this account's.
struct NodeStatus {
    var state = "unjoined"
    var coordinatorHost: String?
    var name: String?
    var userCode: String?
    var managedBy: String?
    var errorMessage: String?
    var errorCode: String?

    static let paths = [
        "/Library/Application Support/Oarbank/status/node.json",
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Oarbank/status/node.json").path,
    ]

    static func read() -> NodeStatus {
        var status = NodeStatus()
        guard let path = paths.first(where: { FileManager.default.fileExists(atPath: $0) }),
              let data = FileManager.default.contents(atPath: path),
              let doc = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return status }
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
}

/// A managed-policy value (an MDM profile's forced value comes first in the search list).
func policyValue(_ key: String) -> Any? { CFPreferencesCopyAppValue(key as CFString, policyDomain) }

final class NodeDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSWindowDelegate {
    private var statusItem: NSStatusItem!
    // each item lives twice: in the status item's menu and in the app menu (keyboard shortcuts with Preferences open)
    private var stateItems: [NSMenuItem] = []
    private var detailItems: [NSMenuItem] = []
    private var managedItems: [NSMenuItem] = []
    private var joinItems: [NSMenuItem] = []
    private var statusWindowItems: [NSMenuItem] = []
    private var preferences: NSWindow?
    private var startup: NSButton?
    private var startupNote: NSTextField?
    private var child: Process?
    private var joinURL: URL?
    private var timer: Timer?
    private var openTimer: Timer?

    func applicationWillFinishLaunching(_ notification: Notification) {
        // before launch finishes, so the link that launched the app is not lost
        NSAppleEventManager.shared().setEventHandler(self, andSelector: #selector(handleURL(_:reply:)),
                                                     forEventClass: AEEventClass(kInternetEventClass), andEventID: AEEventID(kAEGetURL))
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let url = Bundle.main.url(forResource: "oarbank-symbolic", withExtension: "png"), let icon = NSImage(contentsOf: url) {
            icon.size = NSSize(width: 18, height: 18); icon.isTemplate = true
            statusItem.button?.image = icon
        } else { statusItem.button?.title = "O" }
        statusItem.button?.toolTip = "Oarbank Node"
        statusItem.button?.setAccessibilityLabel("Oarbank Node")
        let menu = buildMenu(); menu.delegate = self; statusItem.menu = menu
        // Standard keyboard commands also work when Preferences has focus.
        let main = NSMenu(); let appItem = NSMenuItem(); main.addItem(appItem); appItem.submenu = buildMenu()
        NSApp.mainMenu = main
        refreshStatus()
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { _ in self.refreshStatus() }
        if CommandLine.arguments.contains("--join") { openJoinWindow() }
    }

    private func buildMenu() -> NSMenu {
        let menu = NSMenu(); menu.autoenablesItems = false
        let title = NSMenuItem(title: "Oarbank Node", action: nil, keyEquivalent: ""); title.isEnabled = false
        menu.addItem(title)
        for list in [\NodeDelegate.stateItems, \NodeDelegate.detailItems, \NodeDelegate.managedItems] {
            let item = NSMenuItem(title: "", action: nil, keyEquivalent: ""); item.isEnabled = false; item.isHidden = true
            self[keyPath: list].append(item); menu.addItem(item)
        }
        stateItems.last?.title = "Checking…"; stateItems.last?.isHidden = false
        menu.addItem(.separator())
        for (title, list) in [("Join this Mac…", \NodeDelegate.joinItems), ("Status…", \NodeDelegate.statusWindowItems)] {
            let item = NSMenuItem(title: title, action: #selector(openJoinWindowAction), keyEquivalent: ""); item.target = self
            item.isHidden = true; self[keyPath: list].append(item); menu.addItem(item)
        }
        let prefs = NSMenuItem(title: "Preferences…", action: #selector(showPreferences), keyEquivalent: ",")
        prefs.target = self; menu.addItem(prefs)
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit Oarbank Node", action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self; menu.addItem(quit)
        return menu
    }

    // While the menu is open the status follows the node every 5 s (a menu tracks events in its own run loop mode),
    // otherwise every 30 s: reading one small file.
    func menuWillOpen(_ menu: NSMenu) {
        refreshStatus()
        let t = Timer(timeInterval: 5, repeats: true) { _ in self.refreshStatus() }
        RunLoop.main.add(t, forMode: .common); openTimer = t
    }
    func menuDidClose(_ menu: NSMenu) { openTimer?.invalidate(); openTimer = nil }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool { openJoinWindow(); return false }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func windowDidBecomeKey(_ notification: Notification) { refreshStartup() }

    private func refreshStatus() {
        let status = NodeStatus.read()
        let managedBy = status.managedBy ?? policyValue("ManagedByOrganizationName") as? String
        // AllowUserJoin false hides Join (the join window hides Leave); Status stays, it changes nothing
        let joinAllowed = policyValue("AllowUserJoin") as? Bool != false
        for item in stateItems { item.title = status.summary }
        for item in detailItems { item.title = status.detail ?? ""; item.isHidden = status.detail == nil }
        for item in managedItems { item.title = "Managed by \(managedBy ?? "")"; item.isHidden = managedBy == nil }
        for item in joinItems { item.isHidden = status.hasJoinedOrIsJoining || !joinAllowed }
        for item in statusWindowItems { item.isHidden = !status.hasJoinedOrIsJoining }
        statusItem?.button?.toolTip = "Oarbank Node — \(status.summary)"
    }

    @objc private func handleURL(_ event: NSAppleEventDescriptor, reply: NSAppleEventDescriptor) {
        guard let text = event.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))?.stringValue,
              let url = URL(string: text), url.scheme?.lowercased() == "oarbank" else { return }
        openJoinWindow(link: url.absoluteString)
    }

    @objc private func openJoinWindowAction() { openJoinWindow() }

    /// Runs the join window (the bundled runtime's stdlib server; it opens the browser itself). One already running
    /// from here is reopened at its private link; any other launch is the join window's to fold into an open one. A
    /// link always goes to a new launch, which shows that link's coordinator for confirmation.
    private func openJoinWindow(link: String? = nil) {
        if link == nil, child?.isRunning == true {
            if let url = joinURL { NSWorkspace.shared.open(url) }
            return
        }
        guard FileManager.default.isExecutableFile(atPath: runtimePython), FileManager.default.fileExists(atPath: joinWindow) else {
            alert("Oarbank Node is incomplete", "The join window is missing. Install the Oarbank node package again.")
            return
        }
        let task = Process(); task.executableURL = URL(fileURLWithPath: runtimePython)
        task.arguments = ["-I", joinWindow, "--launcher", launcher] + (link.map { ["--link", $0] } ?? [])
        task.standardError = FileHandle.nullDevice
        let output = Pipe(); task.standardOutput = output
        output.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            guard let text = String(data: data, encoding: .utf8) else { return }
            let prefix = "Open this private link on this computer: "
            for line in text.components(separatedBy: "\n") where line.hasPrefix(prefix) {
                if let url = URL(string: String(line.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)),
                   url.scheme == "http", url.host == "127.0.0.1" {
                    DispatchQueue.main.async { if self.child === task { self.joinURL = url } }
                }
            }
        }
        task.terminationHandler = { process in DispatchQueue.main.async {
            if self.child === process { self.child = nil; self.joinURL = nil }
            self.refreshStatus()
            if process.terminationStatus != 0 && process.terminationReason == .exit {
                self.alert("Could not open the join window", "Choose Join this Mac… again to retry, or run sudo oarbank-node join in Terminal.")
            }
        }}
        do {
            try task.run()
            if link == nil || child?.isRunning != true { child = task; joinURL = nil }
        } catch { alert("Could not open the join window", error.localizedDescription) }
    }

    @objc private func showPreferences() {
        if preferences == nil {
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 440, height: 225), styleMask: [.titled, .closable], backing: .buffered, defer: false)
            window.title = "Oarbank Node Preferences"; window.isReleasedWhenClosed = false; window.delegate = self
            let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 14
            stack.translatesAutoresizingMaskIntoConstraints = false
            let heading = NSTextField(labelWithString: "Oarbank Node"); heading.font = .boldSystemFont(ofSize: 18); stack.addArrangedSubview(heading)
            let checkbox = NSButton(checkboxWithTitle: "Start automatically at sign-in", target: self, action: #selector(toggleStartup))
            startup = checkbox; stack.addArrangedSubview(checkbox)
            let note = NSTextField(wrappingLabelWithString: ""); note.font = .systemFont(ofSize: 13); note.textColor = .secondaryLabelColor
            startupNote = note; stack.addArrangedSubview(note)
            let settings = NSButton(title: "Open Login Items…", target: self, action: #selector(openLoginItems)); stack.addArrangedSubview(settings)
            let lifetime = NSTextField(wrappingLabelWithString: "Quitting this menu bar app leaves this Mac's node running and joined. Automatic startup opens the menu bar app quietly.")
            lifetime.font = .systemFont(ofSize: 13); lifetime.textColor = .secondaryLabelColor; stack.addArrangedSubview(lifetime)
            window.contentView!.addSubview(stack)
            NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 24), stack.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -24), stack.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 22)])
            window.center(); preferences = window
        }
        refreshStartup(); preferences?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    private func refreshStartup() {
        let state = SMAppService.mainApp.status
        startup?.state = state == .enabled ? .on : state == .requiresApproval ? .mixed : .off
        startupNote?.stringValue = state == .requiresApproval ? "macOS requires your approval in Login Items before automatic startup can run." : "Applies to your account. You can also manage this in macOS Login Items."
    }
    @objc private func toggleStartup(_ sender: NSButton) {
        do {
            if sender.state == .off { try SMAppService.mainApp.unregister() }
            else { try SMAppService.mainApp.register() }
        } catch { alert("Could not change automatic startup", error.localizedDescription) }
        refreshStartup()
    }
    @objc private func openLoginItems() { SMAppService.openSystemSettingsLoginItems() }
    @objc private func quitApp() { NSApp.terminate(nil) }
    private func alert(_ title: String, _ detail: String) { NSApp.activate(ignoringOtherApps: true); let alert = NSAlert(); alert.messageText = title; alert.informativeText = detail; alert.runModal() }
    func applicationWillTerminate(_ notification: Notification) { timer?.invalidate(); openTimer?.invalidate(); if let item = statusItem { NSStatusBar.system.removeStatusItem(item) } }
}
let application = NSApplication.shared
let delegate = NodeDelegate()
application.delegate = delegate
application.setActivationPolicy(.accessory)
application.run()
