# Coordinator desktop companion

The native application offers a compact menu: coordinator status, **Open web app**,
**Preferences…**, and **Quit Oarbank Coordinator**. Login remains in the browser.
Preferences contains **Start automatically at sign-in**, off until the user enables
it. Automatic startup opens the companion quietly. Quitting closes the companion;
it does not stop the separately managed coordinator and console services.

The companion runs as the signed-in user. Status probes only the loopback console
health endpoint, ignores environment proxies, does not follow redirects, and exposes
no account credentials, owner keys or enrollment secrets. Opening a configured
coordinator goes to its normal login page. Unfinished setup uses the existing wizard;
on Windows only that explicit action requests elevation. A private loopback wizard
record allows subsequent launches to reopen a live, authenticated setup session.
A stale or externally addressed record cannot redirect the browser.

## Platform decisions and research

- **macOS:** AppKit `NSStatusItem` and standard `NSMenu` provide native click,
  keyboard and accessibility behavior. A simplified monochrome oar image is an
  `NSImage` template, so macOS supplies the appropriate light/dark appearance.
  Preferences is a native window, with Command-comma and Command-Q. Registration
  uses `SMAppService.mainApp`; the OS is the source of truth and a pending approval
  is shown explicitly with a shortcut to Login Items. No private APIs or hand-made
  LaunchAgent are used for this preference. See [Apple NSStatusBar](https://developer.apple.com/documentation/appkit/nsstatusbar)
  and [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice).
- **Windows:** a native WinForms `NotifyIcon` and context menu respond to left or
  right click. The application is DPI-aware, includes multiple icon resolutions,
  runs without elevation, and has one instance per user/session. A repeat launch
  signals the existing app to open the web UI. The user-controlled HKCU `Run` entry
  registers sign-in startup; Preferences also links to Windows Startup Apps, which
  may disable that registration. The MSI closes the companion before replacing or
  removing its executable. See [Microsoft notification-area guidance](https://learn.microsoft.com/en-us/windows/win32/shell/notification-area),
  [NotifyIcon](https://learn.microsoft.com/en-us/dotnet/api/system.windows.forms.notifyicon),
  and [Run keys](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys).
- **Linux:** GTK/GIO exports StatusNotifierItem and DBusMenu on the user's session
  bus, usable under X11 and Wayland. GTK application registration prevents duplicate
  icons. A regular GTK control window remains available when the desktop has no
  compatible tray host, including GNOME configurations without an indicator
  extension. This avoids obsolete XEmbed APIs and a dependency on the deprecated
  GTK Ayatana library. Preferences writes only its own per-user XDG autostart entry,
  with a background argument; custom entries are preserved. See the
  [StatusNotifier specification](https://specifications.freedesktop.org/status-notifier-item/latest/),
  [desktop autostart specification](https://specifications.freedesktop.org/autostart/latest/),
  [GIO application lifecycle](https://docs.gtk.org/gio/class.Application.html),
  and [Ayatana's compatibility change](https://github.com/AyatanaIndicators/libayatana-appindicator-glib).

The menu contains direct actions and a textual status, without animations or
unsolicited notifications. Preferences distinguishes companion startup from service
lifetime. Native platform fonts, keyboard focus, labels and contrast are retained;
critical information never depends solely on an icon or color.

## Enrollment

The wizard generates a complete QR code locally from the existing `otpauth://`
provisioning URI, using issuer/account, SHA-1, six digits and a 30-second interval.
It has an opaque white background and a four-module quiet zone. The secret never
goes to an external QR service. The authenticated, no-cache setup response carries
an embedded PNG; the CSP permits data images, without adding remote image origins.
The QR and raw secret are cleared after completion. Manual entry remains an optional
fallback. Reopening pending setup preserves the original account/address/keys and
asks for the original password. Failed state loading never exposes a blank new-setup
form. See [Google's enrollment URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
and [Segno's local data URI support](https://segno.readthedocs.io/en/latest/web-development.html).

Validation includes independent QR decoding and real OTP completion, the shipped
JavaScript's recovery/cleanup behavior, native Mac compilation and menu inspection,
Windows and Linux native menu/preferences/startup round-trips on disposable runners,
and package upgrade/removal checks. No user's installation is used as a test fixture.
