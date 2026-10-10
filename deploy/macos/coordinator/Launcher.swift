import AppKit
import ServiceManagement

// Oarbank Coordinator: the coordinator's menu bar companion (docs/design/coordinator-desktop.md), run as the person who
// owns the coordinator. Only the explicit Open web app action runs the setup wizard or opens the console. The
// coordinator itself (oarbankd and the console) runs as this account's LaunchAgents with a lifetime of their own: this
// app neither starts nor stops them, and quitting it leaves them running.
//
// The menu bar model is the node app's (deploy/macos/shared/MenuBar.swift, docs/design/node-enrollment.md "Menu bar and
// tray"): one setting, "Show Oarbank Coordinator in the menu bar" (on: the item is shown and the app opens at login;
// off, "Hide from Menu Bar" or ⌘Q: the app leaves the menu bar and quits). And one item per Mac: when Oarbank Node is
// installed here too, this menu shows this Mac's node (its status, Join, its window) and Oarbank Node shows no item.
//
// Launch contract: `--open-web` opens the web app at once (Oarbank Node's Open Console); `--settings`, or a launch with
// the item hidden, opens the settings window; reopening the app opens the web app, or the window while the item is hidden.

let coordinatorJobPlists = ["oarbankd", "console"].map {
    FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/dev.codonic.oarbank.\($0).plist").path
}
let coordinatorSwitchedOffMessage = "The coordinator is turned off in Login Items → Allow in the Background. Turn Oarbank Coordinator back on there."

final class CoordinatorDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSWindowDelegate {
    private var statusItem: NSStatusItem?
    private let setting = MenuBarSetting()
    private var stateText = "Checking coordinator…"
    // each menu row lives twice: the status item's menu and the app menu (keyboard shortcuts while the window has focus)
    private var stateItems: [NSMenuItem] = []
    private var switchedOffItems: [NSMenuItem] = []
    private var nodeItems: [NSMenuItem] = []          // the "This Mac's node" section, shown when Oarbank Node is here
    private var nodeStateItems: [NSMenuItem] = []
    private var nodeDetailItems: [NSMenuItem] = []
    private var nodeSwitchedOffItems: [NSMenuItem] = []
    private var nodeJoinItems: [NSMenuItem] = []
    private var hideItems: [NSMenuItem] = []
    // the window: "This Mac's coordinator" and "Menu bar"
    private var window: NSWindow?
    private let serviceLabel = bodyLabel()
    private let stateLabel = bodyLabel()
    private let switchedOffLabel = bodyLabel(coordinatorSwitchedOffMessage)
    private var switchedOffButton: NSButton!
    private var showToggle: NSButton!
    private let menuBarNote = bodyLabel(secondary: true)
    private var approvalButton: NSButton!
    private var statusTask: Process?
    private var child: Process?
    private var setupURL: URL?
    private var timer: Timer?
    private let root = Bundle.main.resourceURL!.appendingPathComponent("coordinator")

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Standard keyboard commands (⌘, ⌘Q ⌘W) also work while the window has focus.
        let main = NSMenu(); let appItem = NSMenuItem(); main.addItem(appItem); appItem.submenu = buildMenu()
        let windowItem = NSMenuItem(); main.addItem(windowItem)
        let windowMenu = NSMenu(title: "Window"); windowItem.submenu = windowMenu
        windowMenu.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        NSApp.mainMenu = main
        setting.launched()
        updatePresence()
        refreshStatus()
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { _ in self.updatePresence(); self.refreshStatus() }
        if CommandLine.arguments.contains("--open-web") { openWeb() }
        else if statusItem == nil || CommandLine.arguments.contains("--settings") { showWindow() }
    }

    private func updatePresence() {
        if setting.isOn, statusItem == nil {
            let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
            if let glyph = menuBarGlyph("oarbank-coordinator-symbolic") { item.button?.image = glyph } else { item.button?.title = "O" }
            item.button?.setAccessibilityLabel("Oarbank Coordinator")
            let menu = buildMenu(); menu.delegate = self; item.menu = menu
            statusItem = item
            refreshMenu()
        } else if !setting.isOn, let item = statusItem {
            NSStatusBar.system.removeStatusItem(item)
            statusItem = nil
        }
    }

    private func row(_ title: String, _ list: ReferenceWritableKeyPath<CoordinatorDelegate, [NSMenuItem]>, action: Selector? = nil) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = action == nil ? nil : self
        item.isEnabled = action != nil
        self[keyPath: list].append(item)
        return item
    }

    private func buildMenu() -> NSMenu {
        let menu = NSMenu(); menu.autoenablesItems = false
        let title = NSMenuItem(title: "Oarbank Coordinator", action: nil, keyEquivalent: ""); title.isEnabled = false
        menu.addItem(title)
        menu.addItem(row(stateText, \.stateItems))
        let off = row("Turned off in Login Items…", \.switchedOffItems, action: #selector(openLoginItems))
        off.toolTip = coordinatorSwitchedOffMessage; off.isHidden = true
        off.image = NSImage(systemSymbolName: "exclamationmark.triangle", accessibilityDescription: "Warning")
        menu.addItem(off)
        menu.addItem(.separator())
        let web = NSMenuItem(title: "Open Web App", action: #selector(openWeb), keyEquivalent: "o"); web.target = self
        menu.addItem(web)
        // This Mac's node: Oarbank Node shows no item of its own where the coordinator's is
        let nodeSeparator = NSMenuItem.separator(); nodeItems.append(nodeSeparator); menu.addItem(nodeSeparator)
        let header = NSMenuItem.sectionHeader(title: "This Mac’s Node"); nodeItems.append(header); menu.addItem(header)
        for item in [row("", \.nodeStateItems), row("", \.nodeDetailItems)] { nodeItems.append(item); menu.addItem(item) }
        let nodeOff = row("Turned off in Login Items…", \.nodeSwitchedOffItems, action: #selector(openLoginItems))
        nodeOff.toolTip = switchedOffMessage
        nodeOff.image = NSImage(systemSymbolName: "exclamationmark.triangle", accessibilityDescription: "Warning")
        nodeItems.append(nodeOff); menu.addItem(nodeOff)
        let join = row("Join this Mac…", \.nodeJoinItems, action: #selector(joinNode)); nodeItems.append(join); menu.addItem(join)
        let open = NSMenuItem(title: "Oarbank Node…", action: #selector(openNode), keyEquivalent: ""); open.target = self
        nodeItems.append(open); menu.addItem(open)
        menu.addItem(.separator())
        let settings = NSMenuItem(title: "Settings…", action: #selector(showWindowAction), keyEquivalent: ","); settings.target = self
        menu.addItem(settings)
        menu.addItem(.separator())
        // never "Quit": the coordinator is not this app. ⌘Q hides the item (and so quits the app); the coordinator keeps running.
        let hide = NSMenuItem(title: "Hide from Menu Bar", action: #selector(hideFromMenuBar), keyEquivalent: "q")
        hide.target = self; hide.subtitle = "The coordinator keeps running"
        hideItems.append(hide); menu.addItem(hide)
        return menu
    }

    func menuWillOpen(_ menu: NSMenu) { refreshStatus(); refreshMenu() }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if statusItem == nil { showWindow() } else { openWeb() }
        return false
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func windowDidBecomeKey(_ notification: Notification) { refreshStatus(); refreshWindow() }
    func windowWillClose(_ notification: Notification) { DispatchQueue.main.async { self.quitIfIdle() } }

    /// With no menu bar item, no window and no setup wizard to wait for, there is nothing left of this app to show.
    private func quitIfIdle() {
        guard statusItem == nil, window?.isVisible != true, child?.isRunning != true else { return }
        NSApp.terminate(nil)
    }

    private func process(_ operation: String) -> Process {
        let task = Process(); task.executableURL = root.appendingPathComponent("python/bin/python3.12")
        task.arguments = ["-I", "-B", "-c", "import sys; from oarbank.desktop import main; sys.exit(main())", "--root", root.path] + (operation == "status" ? ["--status"] : [])
        task.standardError = FileHandle.nullDevice
        return task
    }

    private func refreshStatus() {
        guard statusTask == nil else { return }
        let task = process("status"), output = Pipe(); task.standardOutput = output; statusTask = task
        task.terminationHandler = { process in
            let data = output.fileHandleForReading.readDataToEndOfFile()
            let state = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            DispatchQueue.main.async {
                self.statusTask = nil
                if process.terminationStatus != 0 || state == nil { self.stateText = "Status unavailable" }
                else if state?["configured"] as? Bool != true { self.stateText = state?["pending"] as? Bool == true ? "Finish authenticator setup" : "Setup needed" }
                else { self.stateText = state?["online"] as? Bool == true ? "Coordinator online" : "Coordinator offline" }
                self.refreshMenu(); self.refreshWindow()
            }
        }
        do { try task.run() } catch { statusTask = nil; stateText = "Status unavailable"; refreshMenu() }
    }

    private func refreshMenu() {
        let switchedOff = switchedOffInLoginItems(coordinatorJobPlists)
        for item in stateItems { item.title = stateText }
        for item in switchedOffItems { item.isHidden = !switchedOff }
        statusItem?.button?.toolTip = "Oarbank Coordinator — \(switchedOff ? "turned off in Login Items" : stateText)"
        // This Mac's node, when Oarbank Node is installed here
        let nodeHere = Oarbank.app(Oarbank.nodeBundleID) != nil
        let node = NodeStatus.read()
        for item in nodeItems { item.isHidden = !nodeHere }
        for item in nodeStateItems { item.title = node.summary }
        for item in nodeDetailItems { item.title = node.detail ?? ""; item.isHidden = !nodeHere || node.detail == nil }
        for item in nodeSwitchedOffItems { item.isHidden = !nodeHere || !switchedOffInLoginItems(nodeJobPlists) }
        for item in nodeJoinItems { item.isHidden = !nodeHere || node.hasJoinedOrIsJoining || !NodeStatus.joinAllowed }
        // with no item in the menu bar, ⌘Q only closes this window's app: say so, and that the coordinator is not it
        for item in hideItems { item.title = statusItem == nil ? "Quit Oarbank Coordinator" : "Hide from Menu Bar" }
    }

    private func refreshWindow() {
        guard let window else { return }
        let switchedOff = switchedOffInLoginItems(coordinatorJobPlists)
        serviceLabel.stringValue = FileManager.default.fileExists(atPath: coordinatorJobPlists[0])
            ? "Running as background services for your account — they start when you log in, and keep running when this app quits."
            : "Not set up on this Mac yet. Open the web app to set it up."
        serviceLabel.isHidden = switchedOff
        switchedOffLabel.isHidden = !switchedOff; switchedOffButton.isHidden = !switchedOff
        stateLabel.stringValue = stateText
        showToggle.state = setting.isOn ? .on : .off
        menuBarNote.stringValue = setting.needsApproval
            ? "macOS needs your approval in Login Items before Oarbank Coordinator can open at login."
            : setting.isOn
                ? "Shown in the menu bar, and opens when you log in. Turning this off quits Oarbank Coordinator; the coordinator keeps running."
                : "Off: Oarbank Coordinator opens only when you open it from Applications. The coordinator keeps running either way."
        approvalButton.isHidden = !setting.needsApproval
        fitWindow(window)
    }

    @objc private func openWeb() {
        if child?.isRunning == true {
            if let url = setupURL { NSWorkspace.shared.open(url) }
            return
        }
        let task = process("open"), output = Pipe(); task.standardOutput = output; setupURL = nil
        output.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            guard let text = String(data: data, encoding: .utf8) else { return }
            let prefix = "Open this private setup link on this computer: "
            for line in text.components(separatedBy: "\n") where line.hasPrefix(prefix) {
                if let url = URL(string: String(line.dropFirst(prefix.count))), url.scheme == "http", url.host == "127.0.0.1" {
                    DispatchQueue.main.async { self.setupURL = url }
                }
            }
        }
        task.terminationHandler = { process in DispatchQueue.main.async {
            self.child = nil; self.setupURL = nil; self.refreshStatus()
            if process.terminationStatus != 0 { ask("Could not open the coordinator", "Open the web app again to retry. Your saved setup and fleet data are preserved.") }
            self.quitIfIdle()
        }}
        do { try task.run(); child = task } catch { ask("Could not open the coordinator", "The application is incomplete. Reinstall the coordinator package.") }
    }

    @objc private func joinNode() { Oarbank.open(Oarbank.nodeBundleID, arguments: ["--join"]) }
    @objc private func openNode() { Oarbank.open(Oarbank.nodeBundleID) }
    @objc private func showWindowAction() { showWindow() }

    private func showWindow() {
        if window == nil {
            switchedOffButton = NSButton(title: "Open Login Items…", target: self, action: #selector(openLoginItems))
            switchedOffLabel.textColor = .systemOrange
            stateLabel.font = .systemFont(ofSize: NSFont.systemFontSize, weight: .medium)
            let web = NSButton(title: "Open Web App", target: self, action: #selector(openWeb))
            let coordinator = group([serviceLabel, switchedOffLabel, switchedOffButton, stateLabel, buttonRow([web])])
            showToggle = NSButton(checkboxWithTitle: "Show Oarbank Coordinator in the menu bar", target: self, action: #selector(toggleMenuBar))
            showToggle.setAccessibilityHelp("When on, Oarbank Coordinator is in the menu bar and opens when you log in.")
            approvalButton = NSButton(title: "Open Login Items…", target: self, action: #selector(openLoginItems))
            let menuBar = group([showToggle, menuBarNote, approvalButton])
            window = settingsWindow(title: "Oarbank Coordinator", sections: [("This Mac’s coordinator", coordinator), ("Menu bar", menuBar)], delegate: self)
            refreshWindow()
            window?.center()
        }
        window?.makeKeyAndOrderFront(nil)
        refreshWindow()
        refreshStatus()
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func toggleMenuBar(_ sender: NSButton) { setMenuBar(sender.state == .on) }

    private func setMenuBar(_ on: Bool) {
        do { try setting.set(on) } catch {
            ask(on ? "Could not add Oarbank Coordinator to the menu bar" : "Could not remove Oarbank Coordinator from login", error.localizedDescription)
        }
        updatePresence(); refreshMenu(); refreshWindow()
        quitIfIdle()
    }

    @objc private func hideFromMenuBar() {
        guard statusItem != nil else { NSApp.terminate(nil); return }
        guard ask("Hide Oarbank Coordinator from the menu bar?",
                  "The coordinator keeps running. To show Oarbank Coordinator again, open it from Applications and turn on Show Oarbank Coordinator in the menu bar.",
                  buttons: ["Hide", "Cancel"]) else { return }
        window?.close()
        setMenuBar(false)
    }

    @objc private func openLoginItems() { SMAppService.openSystemSettingsLoginItems() }
    func applicationWillTerminate(_ notification: Notification) { timer?.invalidate(); if let item = statusItem { NSStatusBar.system.removeStatusItem(item) } }
}

@main
struct CoordinatorMain {
    static func main() {
        let application = NSApplication.shared
        let delegate = CoordinatorDelegate()
        application.delegate = delegate     // a weak reference: the delegate lives as long as the run loop below
        application.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { application.run() }
    }
}
