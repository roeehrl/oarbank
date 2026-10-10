import AppKit
import Security
import ServiceManagement
import XPC

// Oarbank Node: the node's menu bar front end (docs/design/node-enrollment.md, "Join window: files and launch
// contract"). It shows the status document the agent writes and runs the join window for joining and for status; it
// never joins, holds a code or talks to the coordinator itself. The node's service has a lifetime of its own: quitting
// this app leaves it running.
//
// Launch contract: `--join` opens the join window at once (the pkg's postinstall after a double-click install); an
// `oarbank://join?code=…` link (CFBundleURLTypes) runs it with `--link`, which shows the coordinator and asks before
// anything joins; reopening the app (Finder, `open -a` while it runs) opens the join window too.
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
