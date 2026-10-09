using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Collections.Generic;

// No administrator rights are needed for the tray, login or startup preferences.
// The existing setup broker asks for elevation only when setup is requested.
sealed class CoordinatorTray : Form {
    const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string RunName = "OarbankCoordinator";
    readonly string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
    readonly NotifyIcon icon = new NotifyIcon();
    readonly ContextMenuStrip menu = new ContextMenuStrip();
    readonly ToolStripMenuItem status = new ToolStripMenuItem("Checking coordinator…");
    readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
    readonly EventWaitHandle reopen;
    bool checking, configured, updatingStartup;
    volatile bool quitting;
    Form preferences;
    CheckBox automatic;

    CoordinatorTray(EventWaitHandle signal, bool selfTest) {
        reopen = signal; Text = "Oarbank Coordinator"; ShowInTaskbar = false;
        var unused = Handle; // Marshal all callbacks through this UI thread.
        var title = new ToolStripMenuItem("Oarbank Coordinator"); title.Enabled = false; status.Enabled = false;
        menu.Items.Add(title); menu.Items.Add(status); menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Open web app", null, (s,e) => OpenWeb());
        menu.Items.Add("Preferences…", null, (s,e) => Preferences());
        menu.Items.Add(new ToolStripSeparator()); menu.Items.Add("Quit Oarbank Coordinator", null, (s,e) => Close());
        icon.Icon = new Icon(Path.Combine(root,"oarbank.ico"), SystemInformation.SmallIconSize);
        icon.Text = "Oarbank Coordinator"; icon.ContextMenuStrip = menu;
        icon.MouseClick += (s,e) => { if(e.Button == MouseButtons.Left) menu.Show(Cursor.Position); };
        menu.Opening += (s,e) => RefreshStatus();
        icon.Visible = !selfTest;
        timer.Interval = 30000; timer.Tick += (s,e) => RefreshStatus();
        if(!selfTest) {
            timer.Start(); RefreshStatus();
            Task.Run(() => { while(!quitting && reopen.WaitOne()) { if(!quitting) BeginInvoke((Action)OpenWeb); } });
        }
    }
    protected override void SetVisibleCore(bool value) { base.SetVisibleCore(false); }
    string Python { get { return Path.Combine(root,"python","python.exe"); } }
    static string Q(string value) { return "\"" + value + "\""; }
    string Arguments(bool statusOnly) { return "-I -B -c " + Q("import sys; from oarbank.desktop import main; sys.exit(main())") + " --root " + Q(root) + (statusOnly ? " --status" : ""); }

    Dictionary<string,object> ReadStatus() {
        using(var process = new Process()) {
            process.StartInfo = new ProcessStartInfo(Python,Arguments(true)) { UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=root };
            process.Start();
            var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
            if(!process.WaitForExit(8000)) { process.Kill(); throw new IOException("Status timed out."); }
            if(process.ExitCode != 0) throw new IOException("Status unavailable.");
            return new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(stdout.Result);
        }
    }
    void RefreshStatus() {
        if(checking || quitting) return; checking = true;
        Task.Run(() => {
            Dictionary<string,object> result=null;
            try { result=ReadStatus(); } catch { }
            if(quitting) return;
            BeginInvoke((Action)(() => {
                checking=false;
                configured=result!=null && (bool)result["configured"];
                status.Text=result==null ? "Status unavailable" : !configured ? ((bool)result["pending"] ? "Finish authenticator setup" : "Setup needed") : (bool)result["online"] ? "Coordinator online" : "Coordinator offline";
                icon.Text="Oarbank Coordinator — " + status.Text;
            }));
        });
    }
    void OpenWeb() {
        try {
            if(configured) {
                Process.Start(new ProcessStartInfo(Python,Arguments(false)) { UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=root });
            } else {
                // This broker elevates the bundled wizard, never the resident tray app.
                Process.Start(new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File " + Q(Path.Combine(root,"oarbank-setup.ps1"))) { UseShellExecute=true,WindowStyle=ProcessWindowStyle.Hidden,WorkingDirectory=root });
            }
        } catch(Exception error) { Error("Could not open the coordinator",error.Message); }
    }
    bool StartupEnabled() {
        using(var key=Registry.CurrentUser.OpenSubKey(RunKey)) {
            return key!=null && String.Equals(key.GetValue(RunName) as string,StartupCommand(),StringComparison.OrdinalIgnoreCase);
        }
    }
    string StartupCommand() { return Q(Application.ExecutablePath) + " --background"; }
    void SetStartup(bool enabled) {
        using(var key=Registry.CurrentUser.CreateSubKey(RunKey)) {
            if(enabled) key.SetValue(RunName,StartupCommand(),RegistryValueKind.String);
            else if(String.Equals(key.GetValue(RunName) as string,StartupCommand(),StringComparison.OrdinalIgnoreCase)) key.DeleteValue(RunName,false);
        }
    }
    void Preferences() {
        if(preferences==null || preferences.IsDisposed) {
            preferences=new Form { Text="Oarbank Coordinator Preferences",ClientSize=new Size(455,235),FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,StartPosition=FormStartPosition.CenterScreen,AutoScaleMode=AutoScaleMode.Dpi };
            preferences.Icon=new Icon(Path.Combine(root,"oarbank.ico"));
            preferences.Controls.Add(new Label { Text="Oarbank Coordinator",Font=new Font(SystemFonts.MessageBoxFont.FontFamily,14,FontStyle.Bold),AutoSize=true,Location=new Point(22,20) });
            automatic=new CheckBox { Text="Start automatically at sign-in",AutoSize=true,Location=new Point(22,62),AccessibleName="Start automatically at sign-in",Checked=StartupEnabled() };
            automatic.CheckedChanged += (s,e) => { if(updatingStartup) return; try { SetStartup(automatic.Checked); } catch(Exception error) { Error("Could not change automatic startup",error.Message); } finally { updatingStartup=true; automatic.Checked=StartupEnabled(); updatingStartup=false; } };
            preferences.Activated += (s,e) => { updatingStartup=true; automatic.Checked=StartupEnabled(); updatingStartup=false; };
            preferences.Controls.Add(automatic);
            preferences.Controls.Add(new Label { Text="Applies to your account. Windows Startup Apps can also disable automatic startup.",Location=new Point(22,93),Size=new Size(410,36) });
            var settings=new Button { Text="Open Startup Apps…",AutoSize=true,Location=new Point(22,135) };
            settings.Click += (s,e) => { try { Process.Start("ms-settings:startupapps"); } catch(Exception error) { Error("Could not open Startup Apps",error.Message); } };
            preferences.Controls.Add(settings);
            preferences.Controls.Add(new Label { Text="Quitting this tray app leaves coordinator services running.\nAutomatic startup opens the tray app quietly.",Location=new Point(22,177),Size=new Size(410,42) });
        }
        preferences.Show(); preferences.Activate();
    }
    static void Error(string title,string message) { MessageBox.Show(message,title,MessageBoxButtons.OK,MessageBoxIcon.Error); }
    protected override void OnFormClosing(FormClosingEventArgs e) {
        quitting=true; timer.Stop(); icon.Visible=false; icon.Dispose(); menu.Dispose();
        if(preferences!=null) preferences.Close(); reopen.Set();
        base.OnFormClosing(e);
    }
    void SelfTest() {
        if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true") throw new InvalidOperationException("Self-test is only for disposable CI runners.");
        if(menu.Items.Count!=7 || menu.Items[3].Text!="Open web app" || menu.Items[4].Text!="Preferences…") throw new Exception("Tray actions missing.");
        object original;
        using(var key=Registry.CurrentUser.CreateSubKey(RunKey)) original=key.GetValue(RunName);
        try {
            SetStartup(true); if(!StartupEnabled()) throw new Exception("Startup registration failed.");
            SetStartup(false); if(StartupEnabled()) throw new Exception("Startup removal failed.");
            Preferences(); if(automatic.Checked) throw new Exception("Startup is not opt-in.");
            Console.WriteLine("Native tray menu, preferences and per-user startup round-trip passed.");
        } finally {
            using(var key=Registry.CurrentUser.CreateSubKey(RunKey)) { if(original==null) key.DeleteValue(RunName,false); else key.SetValue(RunName,original); }
            Close();
        }
    }
    [STAThread] static void Main(string[] args) {
        Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
        bool created; var sid=WindowsIdentity.GetCurrent().User.Value;
        using(var signal=new EventWaitHandle(false,EventResetMode.AutoReset,"Local\\OarbankCoordinatorTray-"+sid,out created)) {
            if(!created) { if(Array.IndexOf(args,"--background")<0) signal.Set(); return; }
            bool test=Array.IndexOf(args,"--self-test")>=0;
            try { using(var app=new CoordinatorTray(signal,test)) { if(test) app.SelfTest(); else Application.Run(app); } }
            catch(Exception error) { if(test) { Console.Error.WriteLine(error); Environment.ExitCode=1; } else Error("Oarbank Coordinator could not start",error.Message); }
        }
    }
}
