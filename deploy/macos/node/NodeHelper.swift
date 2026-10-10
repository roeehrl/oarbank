import Foundation
import Security
import XPC
import os

// oarbank-node-helper: the node's root helper on macOS (docs/design/node-enrollment.md, "macOS elevation"), installed
// by the pkg as /Library/Oarbank/bin/oarbank-node-helper and run by launchd as the LaunchDaemon
// dev.codonic.oarbank.agent.helper (deploy/macos/dev.codonic.oarbank.agent.helper.plist) when Oarbank Node.app sends
// a request to its Mach service. It does two things, for one client: join this Mac's system service to a fleet and
// make it leave, by running /Library/Oarbank/bin/oarbank-launcher, after an administrator authenticated for that.
//
//   oarbank-node-helper serve             what launchd runs (the Mach service)
//   oarbank-node-helper register-rights   the pkg's postinstall: the authorization rights, with their prompts
//   oarbank-node-helper remove-rights     oarbank-uninstall
//   oarbank-node-helper requirement       print the code signature it requires of its client (package-macos.sh checks
//                                         the app it ships satisfies it)
//
// What it trusts: a connection only from a process whose code signature satisfies the requirement compiled in
// (HelperBuild.swift, written by package-macos.sh: the Developer ID app of the team, or an ad-hoc package's own app by
// its cdhash), checked by XPC on the peer's audit token for every message; a request only once the authorization
// database granted the operation's right on the client's AuthorizationRef, with interaction (the system prompt, which
// names that AuthorizationRef's creator: Oarbank Node). Nothing it receives reaches an argv except a name that passed
// the join window's own rule; the code goes to the launcher's standard input, and progress to the file descriptor the
// app opened (as the person) and passed, so root never opens a path a request named. It logs what ran and how it ended,
// never a code.

let log = Logger(subsystem: "dev.codonic.oarbank", category: "helper")

// ---- the authorization rights
func withAuthorization<T>(_ body: (AuthorizationRef) -> T) -> T? {
    var auth: AuthorizationRef?
    guard AuthorizationCreate(nil, nil, [], &auth) == errAuthorizationSuccess, let ref = auth else { return nil }
    defer { AuthorizationFree(ref, []) }
    return body(ref)
}

/// Root changes the authorization database without a prompt (config.modify.: is-root, else authenticate-admin).
func registerRights() -> Int32 {
    var failed = false
    for op in Elevation.Operation.allCases {
        let status = withAuthorization { ref in
            AuthorizationRightSet(ref, op.right, Elevation.rightDefinition(op) as CFDictionary, op.prompt as CFString, nil, nil)
        } ?? errAuthorizationInternal
        if status != errAuthorizationSuccess {
            FileHandle.standardError.write("oarbank-node-helper: could not register \(op.right) (\(status))\n".data(using: .utf8)!)
            failed = true
        }
    }
    return failed ? 1 : 0
}

func removeRights() -> Int32 {
    for op in Elevation.Operation.allCases {
        _ = withAuthorization { ref in AuthorizationRightRemove(ref, op.right) }
    }
    return 0
}

/// The operation's right on the client's AuthorizationRef, asked with interaction: the system prompt, in the client's
/// session, under the client's name and icon. Success, cancelled, or refused (not an administrator).
func authorize(_ external: Data, _ op: Elevation.Operation) -> OSStatus {
    guard external.count == kAuthorizationExternalFormLength else { return errAuthorizationInvalidRef }
    var form = AuthorizationExternalForm()
    withUnsafeMutableBytes(of: &form) { _ = external.copyBytes(to: $0) }
    var auth: AuthorizationRef?
    let made = AuthorizationCreateFromExternalForm(&form, &auth)
    guard made == errAuthorizationSuccess, let ref = auth else { return made }
    defer { AuthorizationFree(ref, []) }
    // C strings that live until the call returns (AuthorizationItem holds bare pointers)
    var owned: [UnsafeMutablePointer<CChar>] = []
    defer { owned.forEach { free($0) } }
    func c(_ s: String) -> UnsafeMutablePointer<CChar> { let p = strdup(s)!; owned.append(p); return p }
    var env = [(kAuthorizationEnvironmentPrompt, op.prompt)]
    if FileManager.default.fileExists(atPath: Elevation.appIcon) { env.append((kAuthorizationEnvironmentIcon, Elevation.appIcon)) }
    var envItems = env.map { key, value -> AuthorizationItem in
        let v = c(value)
        return AuthorizationItem(name: UnsafePointer(c(key)), valueLength: strlen(v), value: UnsafeMutableRawPointer(v), flags: 0)
    }
    var rightItems = [AuthorizationItem(name: UnsafePointer(c(op.right)), valueLength: 0, value: nil, flags: 0)]
    return rightItems.withUnsafeMutableBufferPointer { r in
        envItems.withUnsafeMutableBufferPointer { e in
            var rights = AuthorizationRights(count: 1, items: r.baseAddress)
            var environment = AuthorizationEnvironment(count: UInt32(e.count), items: e.baseAddress)
            return AuthorizationCopyRights(ref, &rights, &environment, [.extendRights, .interactionAllowed], nil)
        }
    }
}

// ---- running the launcher
enum Run {
    case exited(Int32)
    case failed(String)
}

/// The launcher, root's own: a regular file owned by root that no one else may change (the pkg installs it 0755
/// root:wheel). Anything else and the helper runs nothing.
func launcherIsRoots() -> Bool {
    var st = stat()
    guard lstat(Elevation.launcher, &st) == 0 else { return false }
    return (st.st_mode & S_IFMT) == S_IFREG && st.st_uid == 0 && (st.st_mode & 0o022) == 0
}

/// The progress file the app opened: a regular file of the client's, with one name, open for writing. Root writes to
/// it only what the person could write to it themselves.
func progressIsClients(_ fd: Int32, uid: uid_t) -> Bool {
    var st = stat()
    guard fstat(fd, &st) == 0 else { return false }
    let mode = fcntl(fd, F_GETFL)
    return (st.st_mode & S_IFMT) == S_IFREG && st.st_uid == uid && st.st_nlink == 1 && mode >= 0
        && (mode & O_ACCMODE == O_WRONLY || mode & O_ACCMODE == O_RDWR)
}

/// Run the launcher with `args`, `stdin` on its standard input and `progress` as its fd 3, nothing else inherited (an
/// environment of launchd's own kind, a fresh signal state), and wait for it, an hour at most (the join window's own
/// limit).
func runLauncher(_ args: [String], stdin: String?, progress: Int32) -> Run {
    var pipeFDs: [Int32] = [-1, -1]
    guard pipe(&pipeFDs) == 0 else { return .failed("pipe: \(errno)") }
    defer { close(pipeFDs[0]); if pipeFDs[1] >= 0 { close(pipeFDs[1]) } }
    var actions: posix_spawn_file_actions_t?
    var attr: posix_spawnattr_t?
    posix_spawn_file_actions_init(&actions)
    posix_spawnattr_init(&attr)
    defer { posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attr) }
    posix_spawn_file_actions_adddup2(&actions, pipeFDs[0], 0)
    posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0)
    posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0)
    posix_spawn_file_actions_adddup2(&actions, progress, 3)
    var all = sigset_t(), none = sigset_t()
    sigfillset(&all)
    sigemptyset(&none)
    posix_spawnattr_setsigdefault(&attr, &all)
    posix_spawnattr_setsigmask(&attr, &none)
    // every other descriptor (XPC's, the pipe's write end) closes in the child
    posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK))
    let env = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/root", "USER=root", "LOGNAME=root"]
    var argv = args.map { strdup($0) } + [nil]
    var envp = env.map { strdup($0) } + [nil]
    defer { argv.forEach { free($0) }; envp.forEach { free($0) } }
    var pid: pid_t = 0
    let spawned = posix_spawn(&pid, Elevation.launcher, &actions, &attr, &argv, &envp)
    guard spawned == 0 else { return .failed("spawn: \(spawned)") }
    if let code = stdin {
        var bytes = Array(code.utf8)
        var off = 0
        while off < bytes.count {
            let n = bytes.withUnsafeBytes { write(pipeFDs[1], $0.baseAddress! + off, bytes.count - off) }
            if n <= 0 { break }     // the launcher went away without reading (EPIPE: SIGPIPE is ignored)
            off += n
        }
        for i in bytes.indices { bytes[i] = 0 }
    }
    close(pipeFDs[1])
    pipeFDs[1] = -1
    let deadline = Date().addingTimeInterval(3600)
    var status: Int32 = 0
    while true {
        let r = waitpid(pid, &status, WNOHANG)
        if r == pid { break }
        if r < 0 && errno != EINTR { return .failed("waitpid: \(errno)") }
        if Date() > deadline {
            kill(pid, SIGTERM)
            _ = waitpid(pid, &status, 0)
            return .failed("the launcher did not finish within an hour")
        }
        usleep(100_000)
    }
    // WIFEXITED / WEXITSTATUS, which Swift does not import
    if status & 0x7f == 0 { return .exited((status >> 8) & 0xff) }
    return .exited(128 + (status & 0x7f))
}

// ---- one request
func fields(of message: xpc_object_t) -> [String: Elevation.Field] {
    var out: [String: Elevation.Field] = [:]
    xpc_dictionary_apply(message) { key, value in
        let k = String(cString: key)
        let type = xpc_get_type(value)
        if type == XPC_TYPE_STRING, let s = xpc_string_get_string_ptr(value) {
            out[k] = .string(String(cString: s))
        } else if type == XPC_TYPE_BOOL {
            out[k] = .bool(xpc_bool_get_value(value))
        } else {
            out[k] = .other
        }
        return true
    }
    return out
}

func handle(_ message: xpc_object_t, from peer: xpc_connection_t) -> xpc_object_t? {
    guard let reply = xpc_dictionary_create_reply(message) else { return nil }
    func answer(_ status: String, exit: Int32? = nil, detail: String? = nil) -> xpc_object_t {
        xpc_dictionary_set_string(reply, "status", status)
        if let exit { xpc_dictionary_set_int64(reply, "exit", Int64(exit)) }
        if let detail { xpc_dictionary_set_string(reply, "detail", detail) }
        return reply
    }
    let uid = xpc_connection_get_euid(peer)
    let request: Elevation.Request
    switch Elevation.request(fields(of: message)) {
    case .success(let r): request = r
    case .failure(.refused(let why)):
        log.error("refused a request from uid \(uid, privacy: .public): \(why, privacy: .public)")
        return answer("refused", detail: why)
    }
    var authLength = 0
    guard xpc_get_type(xpc_dictionary_get_value(message, "auth") ?? xpc_null_create()) == XPC_TYPE_DATA,
          let authBytes = xpc_dictionary_get_data(message, "auth", &authLength) else {
        return answer("refused", detail: "no authorization")
    }
    let progress = xpc_dictionary_dup_fd(message, "progress")
    guard progress >= 0 else { return answer("refused", detail: "no progress file") }
    defer { close(progress) }
    guard progressIsClients(progress, uid: uid) else { return answer("refused", detail: "the progress file is not the caller's") }
    guard launcherIsRoots() else { return answer("refused", detail: "\(Elevation.launcher) is missing or not root's") }
    let status = authorize(Data(bytes: authBytes, count: authLength), request.op)
    switch status {
    case errAuthorizationSuccess: break
    case errAuthorizationCanceled:
        log.info("\(request.op.rawValue, privacy: .public) for uid \(uid, privacy: .public): the prompt was dismissed")
        return answer("cancelled")
    default:
        log.notice("\(request.op.rawValue, privacy: .public) for uid \(uid, privacy: .public): not authorized (\(status, privacy: .public))")
        return answer("denied", detail: "\(status)")
    }
    switch runLauncher(Elevation.launcherArguments(request), stdin: request.code, progress: progress) {
    case .exited(let code):
        log.notice("\(request.op.rawValue, privacy: .public) for uid \(uid, privacy: .public): the launcher exited \(code, privacy: .public)")
        return answer("ok", exit: code)
    case .failed(let why):
        log.error("\(request.op.rawValue, privacy: .public) for uid \(uid, privacy: .public): \(why, privacy: .public)")
        return answer("failed", detail: why)
    }
}

// ---- the Mach service
/// One queue for everything: one launcher run at a time (a second request waits for the first), and the bookkeeping
/// the idle timer reads needs no lock. launchd starts the helper again for the next message once it has exited.
let queue = DispatchQueue(label: "dev.codonic.oarbank.agent.helper")
var connections = 0
var lastActivity = Date()

func serve(requirement: String) -> Never {
    signal(SIGPIPE, SIG_IGN)
    let listener = xpc_connection_create_mach_service(Elevation.machService, queue, UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER))
    xpc_connection_set_event_handler(listener) { event in
        guard xpc_get_type(event) == XPC_TYPE_CONNECTION else { return }
        let peer = event as xpc_connection_t
        // checked by the system against the peer's audit token for each message; a peer that does not satisfy it
        // gets XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT and its messages never reach the handler below
        guard xpc_connection_set_peer_code_signing_requirement(peer, requirement) == 0 else {
            xpc_connection_cancel(peer)
            return
        }
        connections += 1
        lastActivity = Date()
        xpc_connection_set_target_queue(peer, queue)
        xpc_connection_set_event_handler(peer) { message in
            lastActivity = Date()
            if xpc_get_type(message) == XPC_TYPE_ERROR {
                if message === XPC_ERROR_CONNECTION_INVALID { connections -= 1 }
                if message === XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT {
                    log.error("refused a client whose code signature is not Oarbank Node's")
                }
                return
            }
            guard xpc_get_type(message) == XPC_TYPE_DICTIONARY, let reply = handle(message, from: peer) else { return }
            xpc_connection_send_message(peer, reply)
            lastActivity = Date()
        }
        xpc_connection_activate(peer)
    }
    xpc_connection_activate(listener)
    // nothing to keep in memory between requests: leave after a minute with no client
    let idle = DispatchSource.makeTimerSource(queue: queue)
    idle.schedule(deadline: .now() + 30, repeating: 30)
    idle.setEventHandler { if connections <= 0 && Date().timeIntervalSince(lastActivity) > 60 { exit(0) } }
    idle.resume()
    dispatchMain()
}

@main
struct NodeHelper {
    static func main() {
        guard let requirement = Elevation.requirement(helperClientPin) else {
            FileHandle.standardError.write("oarbank-node-helper: built without a valid client requirement\n".data(using: .utf8)!)
            exit(78)
        }
        switch CommandLine.arguments.dropFirst().first {
        case "serve": serve(requirement: requirement)
        case "register-rights": exit(registerRights())
        case "remove-rights": exit(removeRights())
        case "requirement": print(requirement); exit(0)
        default:
            FileHandle.standardError.write("usage: oarbank-node-helper serve | register-rights | remove-rights | requirement\n".data(using: .utf8)!)
            exit(64)
        }
    }
}
