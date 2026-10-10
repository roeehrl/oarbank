using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

// Oarbank Node, the node's tray app on Windows (docs/design/node-enrollment.md, "Join window: files and launch
// contract"). It shows the status document the agent writes (%ProgramData%\Oarbank\status\node.json), offers Join this
// PC or Status (both the join window, run by the node runtime's pythonw.exe) and Start at sign-in, and what became of
// container support when it was asked for (HKLM\SOFTWARE\Codonic\Oarbank\ContainerSupport, written by the task the
// installer leaves: rust/crates/oarbank-launcher/src/container_support.rs). It never needs
// administrator rights: the join window asks Windows (UAC) only for the join itself. One instance per session: a second
// launch with --join or --link opens the join window itself (which reopens one already open), a plain second launch
// asks the running instance to.
//
//   "Oarbank Node.exe" [--join | --link oarbank://join?code=... | --background | --self-test]
//
// Built by scripts/package-windows.ps1 with the .NET Framework 4 compiler (C# 5), as the coordinator's tray app is.
sealed class NodeTray : Form {
    const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string RunName = "OarbankNode";
    // managed policy (rust/crates/oarbank-agent/src/policy.rs; the ADMX template in deploy/windows/admx)
    const string PolicyKey = @"SOFTWARE\Policies\Codonic\Oarbank\Agent";
    const string AgentService = "dev.codonic.oarbank.agent";
    // container support's outcome (State, Detail), written by LocalSystem only (container_support.rs)
    const string ContainerSupportKey = @"SOFTWARE\Codonic\Oarbank\ContainerSupport";
    const int FastRefresh = 5000, SlowRefresh = 30000;
    static readonly string Root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
    readonly NotifyIcon icon = new NotifyIcon();
    readonly ContextMenuStrip menu = new ContextMenuStrip();
    readonly ToolStripMenuItem status = new ToolStripMenuItem("Checking…");
    readonly ToolStripMenuItem managed = new ToolStripMenuItem("");
    readonly ToolStripMenuItem containers = new ToolStripMenuItem("");
    readonly ToolStripMenuItem join = new ToolStripMenuItem("Join this PC…");
    readonly ToolStripMenuItem details = new ToolStripMenuItem("Status…");
    readonly ToolStripMenuItem startup = new ToolStripMenuItem("Start at sign-in");
    readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
    readonly EventWaitHandle reopen;
    volatile bool quitting;

    NodeTray(EventWaitHandle signal, bool selfTest) {
        reopen = signal; Text = "Oarbank Node"; ShowInTaskbar = false;
        var unused = Handle; // Marshal all callbacks through this UI thread.
        var title = new ToolStripMenuItem("Oarbank Node"); title.Enabled = false; status.Enabled = false; managed.Enabled = false; containers.Enabled = false;
        menu.Items.Add(title); menu.Items.Add(status); menu.Items.Add(managed); menu.Items.Add(containers); menu.Items.Add(new ToolStripSeparator());
        join.Click += (s,e) => Request(null);
        details.Click += (s,e) => Request(null);
        menu.Items.Add(join); menu.Items.Add(details); menu.Items.Add(new ToolStripSeparator());
        startup.Click += (s,e) => ToggleStartup();
        menu.Items.Add(startup); menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Quit Oarbank Node", null, (s,e) => Close());
        icon.Icon = LoadIcon();
        icon.Text = "Oarbank Node"; icon.ContextMenuStrip = menu;
        icon.MouseClick += (s,e) => { if(e.Button == MouseButtons.Left) menu.Show(Cursor.Position); };
        // refreshed every 5 s while the menu is open, every 30 s otherwise (the tooltip)
        menu.Opening += (s,e) => RefreshStatus();
        menu.Opened += (s,e) => { timer.Interval = FastRefresh; };
        menu.Closed += (s,e) => { timer.Interval = SlowRefresh; };
        icon.Visible = !selfTest;
        timer.Interval = SlowRefresh; timer.Tick += (s,e) => RefreshStatus();
        RefreshStatus();
        if(!selfTest) {
            timer.Start();
            Task.Run(() => { while(!quitting && reopen.WaitOne()) { if(!quitting) BeginInvoke((Action)(() => Request(null))); } });
        }
    }
    protected override void SetVisibleCore(bool value) { base.SetVisibleCore(false); }

    static Icon LoadIcon() {
        var file = Path.Combine(Root, "oarbank.ico");
        try { if(File.Exists(file)) return new Icon(file, SystemInformation.SmallIconSize); } catch { }
        return Icon.ExtractAssociatedIcon(Application.ExecutablePath);
    }

    // MARK: the status document and managed policy

    static string StatusPath {
        get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Oarbank", "status", "node.json"); }
    }

    // The agent replaces the file whole (a temporary file and a rename): a read sees an old or a new document, never half.
    internal static Dictionary<string,object> ReadStatus() {
        try { return new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(File.ReadAllText(StatusPath, Encoding.UTF8)); }
        catch { return null; }
    }

    static string S(Dictionary<string,object> d, string key) {
        object v;
        return d != null && d.TryGetValue(key, out v) && v != null ? Convert.ToString(v, CultureInfo.InvariantCulture).Trim() : "";
    }

    static string Host(string url) {
        Uri u;
        return Uri.TryCreate(url, UriKind.Absolute, out u) && u.Host.Length > 0 ? u.Host : url;
    }

    internal static bool IsJoined(Dictionary<string,object> st) {
        var state = S(st, "state");
        return state == "joined" || state == "connected" || state == "offline";
    }

    // 1 running, 0 installed but not running, -1 not installed or unknown
    static int AgentServiceState() {
        try { using(var sc = new ServiceController(AgentService)) return sc.Status == ServiceControllerStatus.Running ? 1 : 0; }
        catch { return -1; }
    }

    // The menu's status line: Not joined, Joining, Waiting for approval, Connected to <host>, Offline, Joining failed.
    internal static string Describe(Dictionary<string,object> st, int service) {
        var state = S(st, "state");
        var host = Host(S(st, "coordinator"));
        var error = st != null && st.ContainsKey("error") ? st["error"] as Dictionary<string,object> : null;
        var message = S(error, "message"); if(message.Length == 0) message = S(error, "code");
        string text;
        switch(state) {
            case "": case "unjoined": text = "Not joined"; break;
            case "checking": case "joining":
                text = "Joining" + (host.Length > 0 ? " " + host : "") + "…"; break;
            case "pending":
                var code = S(st, "user_code");
                text = "Waiting for approval" + (code.Length > 0 ? " (code " + code + ")" : ""); break;
            case "joined": text = "Joined; connecting to " + host; break;
            case "connected": text = "Connected to " + host; break;
            case "offline": text = "Offline" + (message.Length > 0 ? ": " + message : ""); break;
            case "error":
                // a network error while redeeming a code is retried; anything else ended the attempt
                text = S(st, "retrying") == "True" ? "Joining, retrying: " + message : "Joining failed: " + message; break;
            default: text = state; break;
        }
        if(service == 0) text = IsJoined(st) ? "Offline: the Oarbank agent service is not running" : text + " (the Oarbank agent service is not running)";
        else if(service < 0 && st == null) text = "Not joined (the Oarbank agent is not set up; repair Oarbank)";
        return text;
    }

    static object PolicyValue(string name) {
        try {
            using(var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using(var key = hklm.OpenSubKey(PolicyKey)) return key == null ? null : key.GetValue(name);
        } catch { return null; }
    }

    // AllowUserJoin=0 (REG_DWORD, or "false" as text, as the agent reads it) hides Join: the organization joins the PC
    internal static bool UserJoinAllowed() {
        var v = PolicyValue("AllowUserJoin");
        if(v is int) return (int)v != 0;
        var s = v as string;
        if(s != null) { s = s.Trim().ToLowerInvariant(); return !(s == "0" || s == "false" || s == "no"); }
        return true;
    }

    // Container support asked for at install (CONTAINERS=1, a code made for container jobs, oarbank-node join
    // --containers) and not finished: the same lines as `oarbank-node status` (container_support.rs, line). Empty: nothing to say.
    internal static string ContainerLine(string state, string detail) {
        switch(state ?? "") {
            case "scheduled": return "Container support installs when setup has finished";
            case "installing": return "Installing container support…";
            case "waiting": return "Container support waits for another installation; it continues when Windows restarts";
            case "restart": return "Restart Windows to finish container support";
            case "failed": return String.IsNullOrEmpty(detail) ? "Container support failed" : "Container support failed: " + detail;
            default: return "";
        }
    }

    static string ContainerSupport() {
        try {
            using(var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using(var key = hklm.OpenSubKey(ContainerSupportKey)) {
                if(key == null) return "";
                return ContainerLine(Convert.ToString(key.GetValue("State"), CultureInfo.InvariantCulture), Convert.ToString(key.GetValue("Detail"), CultureInfo.InvariantCulture));
            }
        } catch { return ""; }
    }

    static string ManagedBy(Dictionary<string,object> st) {
        var name = S(st, "managed_by");
        return name.Length > 0 ? name : (Convert.ToString(PolicyValue("ManagedByOrganizationName"), CultureInfo.InvariantCulture) ?? "").Trim();
    }

    void RefreshStatus() {
        if(quitting) return;
        var st = ReadStatus();
        var joined = IsJoined(st);
        status.Text = Describe(st, AgentServiceState());
        var org = ManagedBy(st);
        managed.Text = "Managed by " + org; managed.Available = org.Length > 0;
        var support = ContainerSupport();
        containers.Text = support; containers.Available = support.Length > 0;
        join.Available = !joined && UserJoinAllowed();
        details.Available = joined || (S(st, "state") != "unjoined" && S(st, "state").Length > 0);
        try { startup.Checked = StartupEnabled(); } catch { startup.Checked = false; }
        var tip = "Oarbank Node — " + status.Text;
        icon.Text = tip.Length > 63 ? tip.Substring(0, 62) + "…" : tip; // NotifyIcon refuses more than 63 characters
    }

    // MARK: the join window

    // Windows' own rules for one argument (CommandLineToArgvW and the C runtime, which Python uses)
    internal static string Quote(string arg) {
        if(arg.Length > 0 && arg.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0) return arg;
        var b = new StringBuilder("\"");
        for(int i = 0; ; i++) {
            int slashes = 0;
            while(i < arg.Length && arg[i] == '\\') { slashes++; i++; }
            if(i == arg.Length) { b.Append('\\', slashes * 2); break; }
            if(arg[i] == '"') b.Append('\\', slashes * 2 + 1).Append('"');
            else b.Append('\\', slashes).Append(arg[i]);
        }
        return b.Append('"').ToString();
    }

    // Any web page can open an oarbank:// link: only an oarbank: URL of a sane length goes on, and the join window still
    // shows its coordinator and asks before it joins (docs/design/node-enrollment.md, principle 5)
    internal static bool ValidLink(string link) {
        if(link == null || link.Length > 8192 || !link.StartsWith("oarbank:", StringComparison.OrdinalIgnoreCase)) return false;
        foreach(var c in link) if(c < ' ' || c == '\x7f' || c == '"') return false;
        return true;
    }

    static string Python { get { return Path.Combine(Root, "runtime", "pythonw.exe"); } }
    static string JoinWindow { get { return Path.Combine(Root, "join", "join-window.py"); } }
    static string NodeCli { get { return Path.Combine(Root, "oarbank-node.exe"); } }

    internal static string JoinWindowArguments(string link) {
        var a = "-I " + Quote(JoinWindow) + " --launcher " + Quote(NodeCli);
        return link == null ? a : a + " --link " + Quote(link);
    }

    // pythonw.exe has no console window; the join window opens the default browser itself
    static void OpenJoinWindow(string link) {
        if(!File.Exists(Python) || !File.Exists(JoinWindow)) throw new FileNotFoundException("The join window is missing. Repair Oarbank in Settings, Apps.");
        Process.Start(new ProcessStartInfo(Python, JoinWindowArguments(link)) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Root });
    }

    // --join, --link, the menu, a plain second launch: the join window, which shows the node's status once it has joined
    static void Request(string link) {
        try {
            if(link != null && !ValidLink(link)) { Error("Oarbank Node", "This is not an Oarbank join link."); return; }
            var st = ReadStatus();
            if(!IsJoined(st) && !UserJoinAllowed()) {
                var org = ManagedBy(st);
                MessageBox.Show((org.Length > 0 ? org : "Your organization") + " joins this PC to Oarbank. Ask your administrator.", "Oarbank Node", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            OpenJoinWindow(link);
        } catch(Exception error) { Error("Could not open the join window", error.Message); }
    }

    // MARK: Start at sign-in (per user, no administrator rights)

    static string StartupCommand() { return Quote(Application.ExecutablePath) + " --background"; }
    static bool StartupEnabled() {
        using(var key = Registry.CurrentUser.OpenSubKey(RunKey)) {
            return key != null && String.Equals(key.GetValue(RunName) as string, StartupCommand(), StringComparison.OrdinalIgnoreCase);
        }
    }
    static void SetStartup(bool enabled) {
        using(var key = Registry.CurrentUser.CreateSubKey(RunKey)) {
            if(enabled) key.SetValue(RunName, StartupCommand(), RegistryValueKind.String);
            else if(String.Equals(key.GetValue(RunName) as string, StartupCommand(), StringComparison.OrdinalIgnoreCase)) key.DeleteValue(RunName, false);
        }
    }
    void ToggleStartup() {
        try { SetStartup(!StartupEnabled()); } catch(Exception error) { Error("Could not change Start at sign-in", error.Message); }
        try { startup.Checked = StartupEnabled(); } catch { }
    }

    static void Error(string title, string message) { MessageBox.Show(message, title, MessageBoxButtons.OK, MessageBoxIcon.Error); }
    protected override void OnFormClosing(FormClosingEventArgs e) {
        quitting = true; timer.Stop(); icon.Visible = false; icon.Dispose(); menu.Dispose();
        reopen.Set();
        base.OnFormClosing(e);
    }

    // MARK: CI (scripts/ci-windows-msi.ps1 runs it from the installed package)

    static void Expect(bool ok, string what) { if(!ok) throw new Exception(what); }
    static Dictionary<string,object> Doc(string json) { return new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(json); }

    void SelfTest() {
        if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true") throw new InvalidOperationException("Self-test is only for disposable CI runners.");
        Expect(menu.Items.Count == 11 && menu.Items[0].Text == "Oarbank Node" && menu.Items[3] == containers && menu.Items[5].Text == "Join this PC…" &&
               menu.Items[6].Text == "Status…" && menu.Items[8].Text == "Start at sign-in" && menu.Items[10].Text == "Quit Oarbank Node", "Tray menu items missing.");
        Expect(ContainerLine("restart", "") == "Restart Windows to finish container support" &&
               ContainerLine("failed", "no virtualization") == "Container support failed: no virtualization" &&
               ContainerLine("done", "") == "" && ContainerLine(null, null) == "", "container support lines");
        Expect(Describe(Doc("{\"state\":\"unjoined\"}"), 1) == "Not joined", "unjoined");
        Expect(Describe(Doc("{\"state\":\"pending\",\"user_code\":\"WDJB-MJHT\"}"), 1) == "Waiting for approval (code WDJB-MJHT)", "pending");
        Expect(Describe(Doc("{\"state\":\"connected\",\"coordinator\":\"https://build.example:7443\"}"), 1) == "Connected to build.example", "connected");
        Expect(Describe(Doc("{\"state\":\"error\",\"error\":{\"code\":\"E_CODE_USED\",\"message\":\"used\"}}"), 1) == "Joining failed: used", "error");
        Expect(Describe(Doc("{\"state\":\"error\",\"retrying\":true,\"error\":{\"code\":\"E_TCP\",\"message\":\"no answer\"}}"), 1) == "Joining, retrying: no answer", "retrying");
        Expect(Describe(Doc("{\"state\":\"connected\",\"coordinator\":\"https://c:7443\"}"), 0).StartsWith("Offline"), "stopped service");
        Expect(IsJoined(Doc("{\"state\":\"offline\"}")) && !IsJoined(Doc("{\"state\":\"pending\"}")) && !IsJoined(null), "joined states");
        Expect(ValidLink("oarbank://join?code=OB2-0123") && !ValidLink("https://example.com/") && !ValidLink("oarbank://join?code=\" --x") &&
               !ValidLink("oarbank://join\n"), "link checks");
        Expect(Quote(@"C:\Program Files\Oarbank\join\join-window.py") == "\"C:\\Program Files\\Oarbank\\join\\join-window.py\"" &&
               Quote(@"C:\a b\") == "\"C:\\a b\\\\\"" && Quote("a\"b") == "\"a\\\"b\"" && Quote("") == "\"\"" && Quote("plain") == "plain", "argument quoting");
        Expect(JoinWindowArguments("oarbank://join?code=X").EndsWith(" --link oarbank://join?code=X"), "join window arguments");
        // installed: the join window and the node's command line are beside this program
        if(File.Exists(Path.Combine(Root, "oarbank-agent.exe")))
            Expect(File.Exists(Python) && File.Exists(JoinWindow) && File.Exists(NodeCli), "The installed package lacks the join window, its runtime or oarbank-node.exe.");
        object original;
        using(var key = Registry.CurrentUser.CreateSubKey(RunKey)) original = key.GetValue(RunName);
        try {
            SetStartup(true); Expect(StartupEnabled(), "Startup registration failed.");
            SetStartup(false); Expect(!StartupEnabled(), "Startup removal failed.");
            RefreshStatus();
            Console.WriteLine("Native tray menu, status, links and per-user startup round-trip passed. This node: " + status.Text +
                              (containers.Available ? "; " + containers.Text : ""));
        } finally {
            using(var key = Registry.CurrentUser.CreateSubKey(RunKey)) { if(original == null) key.DeleteValue(RunName, false); else key.SetValue(RunName, original); }
            Close();
        }
    }

    static bool Has(string[] args, string flag) { return Array.IndexOf(args, flag) >= 0; }
    static string Value(string[] args, string flag) {
        int i = Array.IndexOf(args, flag);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    [STAThread] static void Main(string[] args) {
        Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
        bool test = Has(args, "--self-test"), background = Has(args, "--background"), joinNow = Has(args, "--join");
        string link = Value(args, "--link");
        bool asked = joinNow || link != null;
        bool created; var sid = WindowsIdentity.GetCurrent().User.Value;
        using(var signal = new EventWaitHandle(false, EventResetMode.AutoReset, "Local\\OarbankNodeTray-" + sid, out created)) {
            if(!created && !test) {
                // one tray per session: this launch only does what it was asked
                if(asked) Request(link); else if(!background) signal.Set();
                return;
            }
            try {
                using(var app = new NodeTray(signal, test)) {
                    if(test) { app.SelfTest(); return; }
                    // a start from the Start menu or the installer opens the join window; a start at sign-in stays quiet
                    if(asked || !background) app.BeginInvoke((Action)(() => Request(link)));
                    Application.Run(app);
                }
            }
            catch(Exception error) { if(test) { Console.Error.WriteLine(error); Environment.ExitCode = 1; } else Error("Oarbank Node could not start", error.Message); }
        }
    }
}
