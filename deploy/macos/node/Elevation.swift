import Foundation

// The macOS elevation contract (docs/design/node-enrollment.md, "macOS elevation"), shared by the two programs that
// speak it and compiled into both: Oarbank Node.app (NodeApp.swift), whose `--elevate` mode the join window runs, and
// the root helper /Library/Oarbank/bin/oarbank-node-helper (NodeHelper.swift), the LaunchDaemon
// dev.codonic.oarbank.agent.helper the pkg installs. Everything here is a pure function of its inputs (no Security, no
// XPC, no file system), so tests/test_node_packages_macos.py compiles it with a checker and runs it.
//
// The flow: the join window runs `Oarbank Node --elevate join …` with the code on standard input; the app makes an
// empty AuthorizationRef, opens the window's progress file itself and sends {op, auth (external form), progress (the
// open file descriptor), code, name, containers} to the helper's Mach service. The helper accepts the connection only
// from a process whose code signature satisfies `clientRequirement` (the signed app), checks every field again, asks
// the authorization database for this operation's right on the app's AuthorizationRef (the system prompt names the
// AuthorizationRef's creator, Oarbank Node, with its icon), and only then runs the launcher with arguments it builds
// itself: the code on the launcher's standard input, progress through the descriptor the app passed (`/dev/fd/3`), so
// root never opens a path a user chose and nothing the app sends reaches an argv except a validated name.

enum Elevation {
    /// The helper's Mach service in launchd's system domain (its LaunchDaemon's label too): only a root-installed
    /// LaunchDaemon can claim it, so the app needs no check of its own on whom it talks to.
    static let machService = "dev.codonic.oarbank.agent.helper"
    static let launcher = "/Library/Oarbank/bin/oarbank-launcher"
    static let appIdentifier = "dev.codonic.oarbank.node"
    static let appIcon = "/Applications/Oarbank Node.app/Contents/Resources/oarbank.icns"
    // the join code's bound (join-window.py MAX_CODE) and the progress path's
    static let maxCode = 4096
    static let maxPath = 1024

    // Exit codes of `--elevate`: the launcher's own (0 joined, 2 usage, 3 pending, …, 8 needs an administrator,
    // docs/design/node-enrollment.md "oarbank-node") pass through; these mean the launcher never ran.
    static let exitUsage: Int32 = 2
    static let exitNotAdministrator: Int32 = 8       // the right was refused: the launcher's E_PRIVILEGE code
    static let exitCancelled: Int32 = 126            // the person dismissed the prompt (pkexec's code: join-window.py)
    static let exitUnavailable: Int32 = 1            // no helper, or it refused the request

    enum Operation: String, CaseIterable {
        case join, leave

        /// The authorization right each operation needs, registered by `oarbank-node-helper register-rights` (the
        /// pkg's postinstall). One right per operation so the prompt says which one is asked for, and so a site
        /// administrator can allow or forbid joining and leaving separately (`security authorizationdb`).
        var right: String { "dev.codonic.oarbank.node.\(rawValue)" }

        /// The prompt the right carries (its default-prompt) and the helper passes with the request.
        var prompt: String {
            switch self {
            case .join: return "Oarbank Node wants to join this Mac to an Oarbank fleet."
            case .leave: return "Oarbank Node wants to make this Mac leave its Oarbank fleet."
            }
        }
    }

    /// A right's definition in the authorization database: an administrator authenticates every time (timeout 0, not
    /// shared: neither a credential cached by another app's prompt nor this one's serves another request), root's own
    /// AuthorizationRefs get no shortcut, and the prompt is the operation's.
    static func rightDefinition(_ op: Operation) -> [String: Any] {
        ["class": "user", "group": "admin", "authenticate-user": true, "allow-root": false, "session-owner": false,
         "shared": false, "timeout": 0, "tries": 10000, "version": 1,
         "comment": "Used by Oarbank Node to \(op == .join ? "join this Mac to an Oarbank fleet" : "make this Mac leave its Oarbank fleet") (the root helper dev.codonic.oarbank.agent.helper).",
         "default-prompt": ["": op.prompt]]
    }

    // ---- which app the helper serves
    /// The code signature the helper requires of its clients, fixed when the package is built (package-macos.sh
    /// writes HelperBuild.swift): a Developer ID app of the team under the app's identifier, or, for a local ad-hoc
    /// package, exactly the app binary that package holds (its cdhash).
    enum ClientPin: Equatable {
        case developerID(team: String)
        case adHoc(cdhash: String)
    }

    static func requirement(_ pin: ClientPin) -> String? {
        switch pin {
        case .developerID(let team):
            guard team.count == 10, team.allSatisfy({ $0.isASCII && ($0.isUppercase || $0.isNumber) }) else { return nil }
            // Apple's anchor, the Developer ID intermediate (6.2.6) and leaf (6.1.13) markers, the team, the identifier:
            // what `codesign -d -r-` prints as a Developer ID app's designated requirement (TN3127)
            return "anchor apple generic and identifier \"\(appIdentifier)\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
                + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(team)\""
        case .adHoc(let cdhash):
            let hex = cdhash.lowercased()
            guard [40, 64].contains(hex.count), hex.allSatisfy({ $0.isHexDigit && $0.isASCII }) else { return nil }
            return "identifier \"\(appIdentifier)\" and cdhash H\"\(hex)\""
        }
    }

    // ---- the request
    struct Request: Equatable {
        var op: Operation
        var code: String?          // join only, never on an argv
        var name: String?
        var containers = false
    }

    /// A node name as the join window allows it: 1–63 of letters, digits, '.', '_' or '-', starting with a letter or
    /// digit (join-window.py, `join`).
    static func validName(_ name: String) -> Bool {
        let bytes = Array(name.utf8)
        func alnum(_ b: UInt8) -> Bool { (48...57).contains(b) || (65...90).contains(b) || (97...122).contains(b) }
        guard (1...63).contains(bytes.count), alnum(bytes[0]) else { return false }
        return bytes.allSatisfy { alnum($0) || $0 == 46 || $0 == 95 || $0 == 45 }
    }

    /// A pasted code as the join window allows it (join-window.py `clean_code`): bounded, printable, whitespace kept for
    /// the launcher's decoder to strip. nil: not a code.
    static func cleanCode(_ raw: String) -> String? {
        let code = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !code.isEmpty, raw.utf8.count <= maxCode else { return nil }
        let bad = code.unicodeScalars.contains { ($0.value < 32 && !["\t", "\r", "\n"].contains($0)) || $0.value == 127 }
        return bad ? nil : code
    }

    /// The fields the app sends, checked again by the helper (the app is trusted to be the app, not to be right):
    /// exactly the keys an operation takes, each of its type. `auth` and `progress` are checked by the helper itself.
    enum Field: Equatable {
        case string(String)
        case bool(Bool)
        case other
    }

    static func request(_ fields: [String: Field]) -> Result<Request, RequestError> {
        guard case .string(let raw)? = fields["op"], let op = Operation(rawValue: raw) else { return .failure(.refused("unknown operation")) }
        let allowed: Set<String> = op == .join ? ["op", "auth", "progress", "code", "name", "containers"] : ["op", "auth", "progress"]
        if let extra = Set(fields.keys).subtracting(allowed).sorted().first { return .failure(.refused("unexpected field \(extra)")) }
        guard fields["auth"] != nil, fields["progress"] != nil else { return .failure(.refused("no authorization or progress file")) }
        var r = Request(op: op)
        guard op == .join else { return .success(r) }
        guard case .string(let code)? = fields["code"], let clean = cleanCode(code) else { return .failure(.refused("no join code")) }
        r.code = clean
        switch fields["name"] {
        case nil: break
        case .string(let name)? where validName(name): r.name = name
        default: return .failure(.refused("bad name"))
        }
        switch fields["containers"] {
        case nil: break
        case .bool(let b)?: r.containers = b
        default: return .failure(.refused("bad containers flag"))
        }
        return .success(r)
    }

    enum RequestError: Error, Equatable {
        case refused(String)
    }

    /// The launcher's argv for a checked request: built here, from the request's fields, never forwarded. The code
    /// goes on standard input, progress to the descriptor the app passed (the helper's child holds it as fd 3).
    static func launcherArguments(_ r: Request) -> [String] {
        switch r.op {
        case .join:
            return [launcher, "join", "--scope", "system", "--code-stdin", "--no-input", "--no-wait", "--progress-file", "/dev/fd/3"]
                + (r.containers ? ["--containers"] : []) + (r.name.map { ["--name", $0] } ?? [])
        case .leave:
            return [launcher, "leave", "--progress-file", "/dev/fd/3"]
        }
    }

    // ---- the app's command line
    /// What `Oarbank Node --elevate …` was asked to do. The join window runs it with the launcher's own arguments for
    /// the two runs it elevates (join-window.py, `elevated_command`):
    ///   --elevate join --code-stdin --no-input --no-wait --progress-file P --scope system [--name N] [--containers]
    ///   --elevate leave --progress-file P
    /// Each flag once, nothing else; the code is always on standard input.
    struct Command: Equatable {
        var op: Operation
        var progress: String
        var name: String?
        var containers = false
    }

    static func command(_ args: [String]) -> Command? {
        guard let first = args.first, let op = Operation(rawValue: first) else { return nil }
        var seen = Set<String>(), progress: String?, name: String?, scope: String?, containers = false
        var i = 1
        while i < args.count {
            let flag = args[i]
            guard !seen.contains(flag) else { return nil }
            seen.insert(flag)
            switch (op, flag) {
            case (_, "--progress-file"), (.join, "--name"), (.join, "--scope"):
                guard i + 1 < args.count else { return nil }
                let value = args[i + 1]
                i += 1
                if flag == "--progress-file" { progress = value } else if flag == "--name" { name = value } else { scope = value }
            case (.join, "--code-stdin"), (.join, "--no-input"), (.join, "--no-wait"): break
            case (.join, "--containers"): containers = true
            default: return nil
            }
            i += 1
        }
        guard let path = progress, path.hasPrefix("/"), path.utf8.count <= maxPath, !path.contains("\0") else { return nil }
        if op == .join {
            guard seen.isSuperset(of: ["--code-stdin", "--no-input", "--no-wait"]), scope == "system" else { return nil }
            if let n = name, !validName(n) { return nil }
        }
        return Command(op: op, progress: path, name: name, containers: containers)
    }
}
