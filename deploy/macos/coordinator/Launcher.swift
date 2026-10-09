import AppKit

// The installed app opens the local setup wizard with the interpreter it ships.
// Installing the package alone never starts services or configures a fleet.
final class CoordinatorDelegate: NSObject, NSApplicationDelegate {
    private var child: Process?
    private var setupURL: URL?
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if let url = setupURL, child?.isRunning == true { NSWorkspace.shared.open(url) }
        return false
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        let root = Bundle.main.resourceURL!.appendingPathComponent("coordinator")
        let task = Process()
        task.executableURL = root.appendingPathComponent("python/bin/python3.12")
        task.arguments = ["-I", "-B", "-c", "from oarbank.setup import main; main()", "--root", root.path]
        let output = Pipe()
        task.standardOutput = output
        output.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            guard let text = String(data: data, encoding: .utf8) else { return }
            let prefix = "Open this private setup link on this computer: "
            for line in text.components(separatedBy: "\n") where line.hasPrefix(prefix) {
                if let url = URL(string: String(line.dropFirst(prefix.count))),
                   url.scheme == "http", url.host == "127.0.0.1" {
                    DispatchQueue.main.async { self.setupURL = url }
                }
            }
        }
        task.standardError = FileHandle.nullDevice
        task.terminationHandler = { process in
            DispatchQueue.main.async {
                if process.terminationStatus != 0 {
                    let alert = NSAlert()
                    alert.messageText = "Oarbank Coordinator could not start"
                    alert.informativeText = "Open the coordinator again. If the problem persists, contact Codonic support. Your fleet data has not been removed."
                    alert.runModal()
                }
                NSApp.terminate(nil)
            }
        }
        do { try task.run(); child = task }
        catch {
            let alert = NSAlert()
            alert.messageText = "Oarbank Coordinator could not start"
            alert.informativeText = "The installed application is incomplete. Download and reinstall the coordinator package."
            alert.runModal()
            NSApp.terminate(nil)
        }
    }
}
let application = NSApplication.shared
let delegate = CoordinatorDelegate()
application.delegate = delegate
application.setActivationPolicy(.regular)
application.run()
