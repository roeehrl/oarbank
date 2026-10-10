import AppKit
import Security
import ServiceManagement
import XPC

// Oarbank Node: the node's menu bar front end (docs/design/node-enrollment.md, "Menu bar and tray" and "Join window:
// files and launch contract"). It shows the status document the agent writes and runs the join window for joining and
// for status; it never joins, holds a code or talks to the coordinator itself. The node is a launchd job with a
// lifetime of its own (a system LaunchDaemon, or for a personal install the account's LaunchAgent): this app neither
// starts nor stops it, and quitting the app leaves it running.
//
// One setting, "Show Oarbank Node in the menu bar" (MenuBarSetting, deploy/macos/shared/MenuBar.swift): on, the item is
// shown and the app opens at login; off ("Hide from Menu Bar", ⌘Q), the app leaves the menu bar, unregisters its login
// item and quits. Managed policy `ShowStatusIcon` decides instead when set. Where Oarbank Coordinator is installed, its
// menu shows this Mac's node and this app shows no item: it opens only for its window and the join window.
//
// Launch contract: `--join` opens the join window at once (the pkg's postinstall after a double-click install); an
// `oarbank://join?code=…` link (CFBundleURLTypes) runs it with `--link`, which shows the coordinator and asks before
// anything joins; `--settings` opens the app's window, and so does a launch with no item to show (hidden, or a
// coordinator Mac) and reopening the app (Finder, Spotlight, `open -a` while it runs).
//
// `--elevate join|leave …` is the join window's, not a person's: it is how a system-service join or leave gets an
// administrator on macOS (docs/design/node-enrollment.md, "macOS elevation"). This signed app asks the root helper
// (oarbank-node-helper, the LaunchDaemon dev.codonic.oarbank.agent.helper) over XPC, the helper asks the authorization
// database, and the system's prompt names Oarbank Node with its icon. The menu bar app itself never handles a code;
// `--elevate` relays the one on its standard input to the helper and exits with the launcher's exit code.

let installRoot = "/Library/Oarbank"
let runtimePython = "\(installRoot)/bin/runtime/bin/python3"
let joinWindow = "\(installRoot)/share/join/join-window.py"
let launcher = "\(installRoot)/bin/oarbank-launcher"

final class NodeDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSWindowDelegate {
    private var statusItem: NSStatusItem?
    private let setting = MenuBarSetting(managed: { Oarbank.policyBool("ShowStatusIcon") })
    // each menu row lives twice: in the status item's menu and in the app menu (keyboard shortcuts while the window has
    // focus, when there is no status item)
    private var stateItems: [NSMenuItem] = []
    private var detailItems: [NSMenuItem] = []
    private var managedItems: [NSMenuItem] = []
    private var switchedOffItems: [NSMenuItem] = []
    private var joinItems: [NSMenuItem] = []
    private var statusWindowItems: [NSMenuItem] = []
    private var hideItems: [NSMenuItem] = []
    // the window: "This Mac's node" and "Menu bar"
    private var window: NSWindow?
    private let serviceLabel = bodyLabel()
    private let stateLabel = bodyLabel()
    private let detailLabel = bodyLabel(secondary: true)
    private let nodeManagedLabel = bodyLabel(secondary: true)
    private let switchedOffLabel = bodyLabel(switchedOffMessage)
    private var switchedOffButton: NSButton!
    private var joinButton: NSButton!
    private var statusButton: NSButton!
    private var consoleButton: NSButton!
    private var showToggle: NSButton!
    private let menuBarNote = bodyLabel(secondary: true)
    private var approvalButton: NSButton!
    private var child: Process?
    private var joinURL: URL?
    private var timer: Timer?
    private var openTimer: Timer?
    private var launchRequest = false

    func applicationWillFinishLaunching(_ notification: Notification) {
        // before launch finishes, so the link that launched the app is not lost
        NSAppleEventManager.shared().setEventHandler(self, andSelector: #selector(handleURL(_:reply:)),
                                                     forEventClass: AEEventClass(kInternetEventClass), andEventID: AEEventID(kAEGetURL))
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Standard keyboard commands (⌘, ⌘Q ⌘W) also work while the window has focus.
        let main = NSMenu(); let appItem = NSMenuItem(); main.addItem(appItem); appItem.submenu = buildMenu()
        let windowItem = NSMenuItem(); main.addItem(windowItem)
        let windowMenu = NSMenu(title: "Window"); windowItem.submenu = windowMenu
        windowMenu.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        NSApp.mainMenu = main
        // a coordinator Mac: the coordinator's menu shows this node, so nothing opens this app at login
        if coordinatorHere { try? setting.set(false) } else { setting.launched() }
        updatePresence()
        refreshStatus()
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { _ in self.updatePresence(); self.refreshStatus() }
        if CommandLine.arguments.contains("--join") { launchRequest = true; openJoinWindow() }
        if CommandLine.arguments.contains("--settings") { launchRequest = true; showWindow() }
        // a launch with nothing to show in the menu bar opens the window (after a link that launched the app has arrived)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            if !self.launchRequest && self.statusItem == nil { self.showWindow() }
        }
    }

    /// Oarbank Coordinator is on this Mac: its menu bar item shows this node.
    private var coordinatorHere: Bool { Oarbank.app(Oarbank.coordinatorBundleID) != nil }

    /// The menu bar item exists exactly while the setting is on and no coordinator on this Mac shows the node instead.
    private func updatePresence() {
        let show = setting.isOn && !coordinatorHere
        if show, statusItem == nil {
            let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
            if let glyph = menuBarGlyph("oarbank-node-symbolic") { item.button?.image = glyph } else { item.button?.title = "O" }
            item.button?.setAccessibilityLabel("Oarbank Node")
            let menu = buildMenu(); menu.delegate = self; item.menu = menu
            statusItem = item
            refreshStatus()
        } else if !show, let item = statusItem {
            NSStatusBar.system.removeStatusItem(item)
            statusItem = nil
        }
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
        let off = NSMenuItem(title: "Turned off in Login Items…", action: #selector(openLoginItems), keyEquivalent: "")
        off.target = self; off.isHidden = true; off.toolTip = switchedOffMessage
        off.image = NSImage(systemSymbolName: "exclamationmark.triangle", accessibilityDescription: "Warning")
        switchedOffItems.append(off); menu.addItem(off)
        menu.addItem(.separator())
        for (title, list) in [("Join this Mac…", \NodeDelegate.joinItems), ("Status…", \NodeDelegate.statusWindowItems)] {
            let item = NSMenuItem(title: title, action: #selector(openJoinWindowAction), keyEquivalent: ""); item.target = self
            item.isHidden = true; self[keyPath: list].append(item); menu.addItem(item)
        }
        let settings = NSMenuItem(title: "Settings…", action: #selector(showWindowAction), keyEquivalent: ",")
        settings.target = self; menu.addItem(settings)
        menu.addItem(.separator())
        // never "Quit": the node is not this app. ⌘Q hides the item (and so quits the app); the node keeps running.
        let hide = NSMenuItem(title: "Hide from Menu Bar", action: #selector(hideFromMenuBar), keyEquivalent: "q")
        hide.target = self; hide.subtitle = "This Mac's node keeps running"
        hideItems.append(hide); menu.addItem(hide)
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
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool { showWindow(); return false }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func windowDidBecomeKey(_ notification: Notification) { refreshStatus() }
    func windowWillClose(_ notification: Notification) { DispatchQueue.main.async { self.quitIfIdle() } }

    /// With no menu bar item, no window and no join window to wait for, there is nothing left of this app to show.
    private func quitIfIdle() {
        guard statusItem == nil, window?.isVisible != true, child?.isRunning != true else { return }
        NSApp.terminate(nil)
    }

    private func refreshStatus() {
        let status = NodeStatus.read()
        let organization = Oarbank.organization(status)
        let joinAllowed = NodeStatus.joinAllowed
        let switchedOff = switchedOffInLoginItems(nodeJobPlists)
        for item in stateItems { item.title = status.summary }
        for item in detailItems { item.title = status.detail ?? ""; item.isHidden = status.detail == nil }
        for item in managedItems { item.title = "Managed by \(organization ?? "")"; item.isHidden = organization == nil }
        for item in switchedOffItems { item.isHidden = !switchedOff }
        for item in joinItems { item.isHidden = status.hasJoinedOrIsJoining || !joinAllowed }
        for item in statusWindowItems { item.isHidden = !status.hasJoinedOrIsJoining }
        // with no item in the menu bar, ⌘Q only closes this window's app: say so, and that the node is not it
        for item in hideItems {
            item.title = statusItem == nil ? "Quit Oarbank Node" : "Hide from Menu Bar"
            item.isEnabled = statusItem == nil || setting.managed != true
        }
        statusItem?.button?.toolTip = "Oarbank Node — \(switchedOff ? "turned off in Login Items" : status.summary)"
        if window?.isVisible == true { refreshWindow(status, organization: organization, joinAllowed: joinAllowed, switchedOff: switchedOff) }
    }

    private func refreshWindow(_ status: NodeStatus, organization: String?, joinAllowed: Bool, switchedOff: Bool) {
        guard let window else { return }
        // This Mac's node
        serviceLabel.stringValue = serviceDescription()
        serviceLabel.isHidden = switchedOff
        switchedOffLabel.isHidden = !switchedOff; switchedOffButton.isHidden = !switchedOff
        stateLabel.stringValue = status.summary
        detailLabel.stringValue = status.detail ?? ""; detailLabel.isHidden = status.detail == nil
        nodeManagedLabel.stringValue = "Managed by \(organization ?? "")"; nodeManagedLabel.isHidden = organization == nil
        joinButton.isHidden = status.hasJoinedOrIsJoining || !joinAllowed
        statusButton.isHidden = !status.hasJoinedOrIsJoining
        consoleButton.isHidden = !coordinatorHere
        // Menu bar
        let managed = setting.managed
        if coordinatorHere {
            showToggle.state = .off; showToggle.isEnabled = false
            menuBarNote.stringValue = "On this Mac, Oarbank Coordinator's menu bar item shows this node."
        } else if managed != nil {
            showToggle.state = managed == true ? .on : .off; showToggle.isEnabled = false
            menuBarNote.stringValue = "Managed by \(organization ?? "your organization")."
        } else {
            showToggle.state = setting.isOn ? .on : .off; showToggle.isEnabled = true
            menuBarNote.stringValue = setting.needsApproval
                ? "macOS needs your approval in Login Items before Oarbank Node can open at login."
                : setting.isOn
                    ? "Shown in the menu bar, and opens when you log in. Turning this off quits Oarbank Node; this Mac's node keeps running."
                    : "Off: Oarbank Node opens only when you open it from Applications. This Mac's node keeps running either way."
        }
        approvalButton.isHidden = !(managed == nil && !coordinatorHere && setting.needsApproval)
        fitWindow(window)
    }

    @objc private func handleURL(_ event: NSAppleEventDescriptor, reply: NSAppleEventDescriptor) {
        guard let text = event.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))?.stringValue,
              let url = URL(string: text), url.scheme?.lowercased() == "oarbank" else { return }
        launchRequest = true
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
            ask("Oarbank Node is incomplete", "The join window is missing. Install the Oarbank node package again.")
            quitIfIdle()
            return
        }
        let task = Process(); task.executableURL = URL(fileURLWithPath: runtimePython)
        // --elevator: this app's own executable, whose --elevate mode the window runs for a system-service join or leave
        task.arguments = ["-I", joinWindow, "--launcher", launcher] + (Bundle.main.executablePath.map { ["--elevator", $0] } ?? [])
            + (link.map { ["--link", $0] } ?? [])
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
                ask("Could not open the join window", "Choose Join this Mac… again to retry, or run sudo oarbank-node join in Terminal.")
            }
            self.quitIfIdle()
        }}
        do {
            try task.run()
            if link == nil || child?.isRunning != true { child = task; joinURL = nil }
        } catch { ask("Could not open the join window", error.localizedDescription) }
    }

    @objc private func showWindowAction() { showWindow() }

    /// The app's window: this Mac's node (its service in plain words, where it is joined, Join or Status) and the
    /// menu bar setting.
    private func showWindow() {
        if window == nil {
            switchedOffButton = NSButton(title: "Open Login Items…", target: self, action: #selector(openLoginItems))
            joinButton = NSButton(title: "Join this Mac…", target: self, action: #selector(openJoinWindowAction))
            statusButton = NSButton(title: "Status…", target: self, action: #selector(openJoinWindowAction))
            consoleButton = NSButton(title: "Open Console", target: self, action: #selector(openConsole))
            consoleButton.toolTip = "Opens this Mac's coordinator in your browser (Oarbank Coordinator)"
            stateLabel.font = .systemFont(ofSize: NSFont.systemFontSize, weight: .medium)
            switchedOffLabel.textColor = .systemOrange
            let node = group([serviceLabel, switchedOffLabel, switchedOffButton, stateLabel, detailLabel, nodeManagedLabel,
                              buttonRow([joinButton, statusButton, consoleButton])])
            showToggle = NSButton(checkboxWithTitle: "Show Oarbank Node in the menu bar", target: self, action: #selector(toggleMenuBar))
            showToggle.setAccessibilityHelp("When on, Oarbank Node is in the menu bar and opens when you log in.")
            approvalButton = NSButton(title: "Open Login Items…", target: self, action: #selector(openLoginItems))
            let menuBar = group([showToggle, menuBarNote, approvalButton])
            window = settingsWindow(title: "Oarbank Node", sections: [("This Mac’s node", node), ("Menu bar", menuBar)], delegate: self)
        }
        let status = NodeStatus.read()
        let firstShow = window?.isVisible != true
        refreshWindow(status, organization: Oarbank.organization(status), joinAllowed: NodeStatus.joinAllowed,
                      switchedOff: switchedOffInLoginItems(nodeJobPlists))
        if firstShow { window?.center() }
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func toggleMenuBar(_ sender: NSButton) {
        setMenuBar(sender.state == .on)
    }

    /// The setting itself: the login item, then the item. Turned off from the window, the app stays until the window
    /// closes; from the menu, it quits at once.
    private func setMenuBar(_ on: Bool) {
        do { try setting.set(on) } catch {
            ask(on ? "Could not add Oarbank Node to the menu bar" : "Could not remove Oarbank Node from login", error.localizedDescription)
        }
        updatePresence()
        refreshStatus()
        quitIfIdle()
    }

    @objc private func hideFromMenuBar() {
        guard statusItem != nil else { NSApp.terminate(nil); return }
        guard setting.managed != true else { return }
        guard ask("Hide Oarbank Node from the menu bar?",
                  "This Mac's node keeps running and stays joined. To show Oarbank Node again, open it from Applications and turn on Show Oarbank Node in the menu bar.",
                  buttons: ["Hide", "Cancel"]) else { return }
        window?.close()
        setMenuBar(false)
    }

    /// The coordinator on this Mac opens its web app (its console).
    @objc private func openConsole() { Oarbank.open(Oarbank.coordinatorBundleID, arguments: ["--open-web"]) }
    @objc private func openLoginItems() { SMAppService.openSystemSettingsLoginItems() }
    func applicationWillTerminate(_ notification: Notification) { timer?.invalidate(); openTimer?.invalidate(); if let item = statusItem { NSStatusBar.system.removeStatusItem(item) } }
}

// ---------------------------------------------------------------- --elevate: the join window's administrator step
/// One line the join window reads from its progress file (join-window.py `Job.lines`), for the failures that happen
/// before the launcher runs and writes its own: the page shows the message and code like the launcher's.
func writeResult(_ fd: Int32, exit: Int32, code: String, message: String) {
    guard fd >= 0, let line = try? JSONSerialization.data(withJSONObject: ["type": "result", "ok": false, "exit": exit, "code": code, "message": message]) else { return }
    let data = line + Data("\n".utf8)
    _ = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) }
}

/// `Oarbank Node --elevate …` (Elevation.command has the grammar): open the progress file as the person, read the code
/// from standard input, make an empty AuthorizationRef, and hand all three to the helper, which asks for the
/// administrator and runs the launcher. Exits with the launcher's exit code, or Elevation's own when it never ran.
func elevate(_ args: [String]) -> Int32 {
    guard let command = Elevation.command(args) else {
        FileHandle.standardError.write(Data("usage: Oarbank Node --elevate join --code-stdin --no-input --no-wait --progress-file PATH --scope system [--name NAME] [--containers] | --elevate leave --progress-file PATH\n".utf8))
        return Elevation.exitUsage
    }
    // opened here, as the person, never by root: the helper writes through this descriptor only
    let progress = open(command.progress, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC)
    var st = stat()
    guard progress >= 0, fstat(progress, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == getuid() else {
        FileHandle.standardError.write(Data("Oarbank Node: \(command.progress) is not this user's progress file\n".utf8))
        return Elevation.exitUsage
    }
    defer { close(progress) }
    var code: String?
    if command.op == .join {
        let data = FileHandle.standardInput.readData(ofLength: Elevation.maxCode + 1)
        guard data.count <= Elevation.maxCode, let text = String(data: data, encoding: .utf8), let clean = Elevation.cleanCode(text) else {
            writeResult(progress, exit: 2, code: "E_CODE_FORMAT", message: "Paste the join code from your Oarbank console.")
            return Elevation.exitUsage
        }
        code = clean
    }
    // the right must be in the authorization database (the pkg's postinstall registers it): without it the system
    // would fall back to a generic rule and prompt
    guard AuthorizationRightGet(command.op.right, nil) == errAuthorizationSuccess else {
        writeResult(progress, exit: 1, code: "E_LOCAL", message: "Oarbank Node's administrator right is missing. Install the Oarbank node package again.")
        return Elevation.exitUnavailable
    }
    // empty: the helper asks for the right on it, with interaction, so the prompt is shown once and names this app
    var auth: AuthorizationRef?
    var external = AuthorizationExternalForm()
    guard AuthorizationCreate(nil, nil, [], &auth) == errAuthorizationSuccess, let ref = auth,
          AuthorizationMakeExternalForm(ref, &external) == errAuthorizationSuccess else {
        writeResult(progress, exit: 1, code: "E_LOCAL", message: "Oarbank Node could not ask for an administrator.")
        return Elevation.exitUnavailable
    }
    defer { AuthorizationFree(ref, [.destroyRights]) }
    let message = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(message, "op", command.op.rawValue)
    withUnsafeBytes(of: &external) { xpc_dictionary_set_data(message, "auth", $0.baseAddress!, $0.count) }
    xpc_dictionary_set_fd(message, "progress", progress)
    if let code { xpc_dictionary_set_string(message, "code", code) }
    if let name = command.name { xpc_dictionary_set_string(message, "name", name) }
    if command.containers { xpc_dictionary_set_bool(message, "containers", true) }
    // the system domain's service: only a LaunchDaemon root installed can hold the name
    let connection = xpc_connection_create_mach_service(Elevation.machService, nil, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
    xpc_connection_set_event_handler(connection) { _ in }
    xpc_connection_activate(connection)
    defer { xpc_connection_cancel(connection) }
    // the reply comes once the person answered the prompt and the launcher exited (join --no-wait: the checks and the
    // service's setup, progress meanwhile in the file the window follows)
    let reply = xpc_connection_send_message_with_reply_sync(connection, message)
    guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY, let status = xpc_dictionary_get_string(reply, "status").map({ String(cString: $0) }) else {
        writeResult(progress, exit: 1, code: "E_LOCAL", message: "Oarbank Node's helper did not answer. Install the Oarbank node package again, or run: sudo oarbank-node \(command.op.rawValue)")
        return Elevation.exitUnavailable
    }
    switch status {
    case "ok": return Int32(clamping: xpc_dictionary_get_int64(reply, "exit"))
    case "cancelled": return Elevation.exitCancelled
    case "denied":
        writeResult(progress, exit: 8, code: "E_PRIVILEGE", message: "Only an administrator of this Mac can do this.")
        return Elevation.exitNotAdministrator
    default:
        let detail = xpc_dictionary_get_string(reply, "detail").map { String(cString: $0) } ?? status
        writeResult(progress, exit: 1, code: "E_LOCAL", message: "Oarbank Node's helper refused: \(detail)")
        return Elevation.exitUnavailable
    }
}

@main
struct NodeMain {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        if args.first == "--elevate" { exit(elevate(Array(args.dropFirst()))) }
        let application = NSApplication.shared
        let delegate = NodeDelegate()
        application.delegate = delegate     // a weak reference: the delegate lives as long as the run loop below
        application.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { application.run() }
    }
}
