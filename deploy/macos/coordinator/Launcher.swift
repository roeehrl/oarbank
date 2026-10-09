import AppKit
import ServiceManagement

// A per-user menu bar companion. Only the explicit Open web app action runs the
// wizard. The coordinator services have a separate lifetime from this app.
final class CoordinatorDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSWindowDelegate {
    private var statusItem: NSStatusItem!
    private let stateItem = NSMenuItem(title: "Checking coordinator…", action: nil, keyEquivalent: "")
    private var applicationStateItem: NSMenuItem?
    private var preferences: NSWindow?
    private var startup: NSButton?
    private var startupNote: NSTextField?
    private var statusTask: Process?
    private var child: Process?
    private var setupURL: URL?
    private var timer: Timer?
    private let root = Bundle.main.resourceURL!.appendingPathComponent("coordinator")

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let url = Bundle.main.url(forResource: "oarbank-symbolic", withExtension: "png"), let icon = NSImage(contentsOf: url) {
            icon.size = NSSize(width: 18, height: 18); icon.isTemplate = true
            statusItem.button?.image = icon
        } else { statusItem.button?.title = "O" }
        statusItem.button?.toolTip = "Oarbank Coordinator"
        statusItem.button?.setAccessibilityLabel("Oarbank Coordinator")
        let menu = NSMenu(); menu.delegate = self; menu.autoenablesItems = false
        let title = NSMenuItem(title: "Oarbank Coordinator", action: nil, keyEquivalent: ""); title.isEnabled = false
        stateItem.isEnabled = false
        menu.addItem(title); menu.addItem(stateItem); menu.addItem(.separator())
        for (title, action, key) in [("Open web app", #selector(openWeb), "o"), ("Preferences…", #selector(showPreferences), ",")] {
            let item = NSMenuItem(title: title, action: action, keyEquivalent: key); item.target = self; menu.addItem(item)
        }
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit Oarbank Coordinator", action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self; menu.addItem(quit); statusItem.menu = menu
        // Standard keyboard commands also work when Preferences has focus.
        let main = NSMenu(); let appItem = NSMenuItem(); main.addItem(appItem); appItem.submenu = menu.copy() as? NSMenu
        applicationStateItem = appItem.submenu?.items[1]
        NSApp.mainMenu = main
        refreshStatus()
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { _ in self.refreshStatus() }
    }

    func menuWillOpen(_ menu: NSMenu) { refreshStatus() }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool { openWeb(); return false }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func windowDidBecomeKey(_ notification: Notification) { refreshStartup() }

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
                let text: String
                if process.terminationStatus != 0 || state == nil { text = "Status unavailable" }
                else if state?["configured"] as? Bool != true { text = state?["pending"] as? Bool == true ? "Finish authenticator setup" : "Setup needed" }
                else { text = state?["online"] as? Bool == true ? "Coordinator online" : "Coordinator offline" }
                self.stateItem.title = text; self.applicationStateItem?.title = text; self.statusItem.button?.toolTip = "Oarbank Coordinator — \(text)"
            }
        }
        do { try task.run() } catch { statusTask = nil; stateItem.title = "Status unavailable" }
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
            if process.terminationStatus != 0 { self.alert("Could not open the coordinator", "Open web app again to retry. Your saved setup and fleet data are preserved.") }
        }}
        do { try task.run(); child = task } catch { alert("Could not open the coordinator", "The application is incomplete. Reinstall the coordinator package.") }
    }

    @objc private func showPreferences() {
        if preferences == nil {
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 440, height: 245), styleMask: [.titled, .closable], backing: .buffered, defer: false)
            window.title = "Oarbank Coordinator Preferences"; window.isReleasedWhenClosed = false; window.delegate = self
            let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 14
            stack.translatesAutoresizingMaskIntoConstraints = false
            let heading = NSTextField(labelWithString: "Oarbank Coordinator"); heading.font = .boldSystemFont(ofSize: 18); stack.addArrangedSubview(heading)
            let checkbox = NSButton(checkboxWithTitle: "Start automatically at sign-in", target: self, action: #selector(toggleStartup))
            startup = checkbox; stack.addArrangedSubview(checkbox)
            let note = NSTextField(wrappingLabelWithString: ""); note.font = .systemFont(ofSize: 13); note.textColor = .secondaryLabelColor
            startupNote = note; stack.addArrangedSubview(note)
            let settings = NSButton(title: "Open Login Items…", target: self, action: #selector(openLoginItems)); stack.addArrangedSubview(settings)
            let lifetime = NSTextField(wrappingLabelWithString: "Quitting this menu bar app leaves coordinator services running. Automatic startup opens the menu bar app quietly.")
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
    func applicationWillTerminate(_ notification: Notification) { timer?.invalidate(); if let item = statusItem { NSStatusBar.system.removeStatusItem(item) } }
}
let application = NSApplication.shared
let delegate = CoordinatorDelegate()
application.delegate = delegate
application.setActivationPolicy(.accessory)
application.run()
