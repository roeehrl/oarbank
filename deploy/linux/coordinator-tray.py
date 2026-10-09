#!/usr/bin/python3
"""Native GTK preferences plus StatusNotifierItem/DBusMenu for X11 and Wayland.

Uses distribution GTK/GIO, avoiding bundled desktop runtimes or deprecated
XEmbed tray APIs. A normal window remains available without a tray host.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

parser = argparse.ArgumentParser(description='Oarbank coordinator tray and preferences')
parser.add_argument('--background', action='store_true')
parser.add_argument('--self-test', action='store_true')
args = parser.parse_args()
if args.self_test and os.environ.get('GITHUB_ACTIONS') != 'true':
    parser.error('Self-test is only for disposable CI runners.')

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gio, GLib, Gtk

spec = importlib.util.spec_from_file_location('autostart', Path(__file__).resolve().with_name('coordinator-autostart.py'))
autostart = importlib.util.module_from_spec(spec)
spec.loader.exec_module(autostart)
ROOT = Path('/opt/oarbank/coordinator')
SNI = 'org.kde.StatusNotifierItem'
MENU = 'com.canonical.dbusmenu'
MENU_PATH = '/Menu'
XML = '''<node><interface name="org.kde.StatusNotifierItem">
<method name="ContextMenu"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
<method name="Activate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
<method name="SecondaryActivate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
<method name="Scroll"><arg type="i" direction="in"/><arg type="s" direction="in"/></method>
<property name="Category" type="s" access="read"/><property name="Id" type="s" access="read"/>
<property name="Title" type="s" access="read"/><property name="Status" type="s" access="read"/>
<property name="WindowId" type="u" access="read"/><property name="IconName" type="s" access="read"/>
<property name="IconPixmap" type="a(iiay)" access="read"/><property name="IconThemePath" type="s" access="read"/>
<property name="OverlayIconName" type="s" access="read"/><property name="OverlayIconPixmap" type="a(iiay)" access="read"/>
<property name="AttentionIconName" type="s" access="read"/><property name="AttentionIconPixmap" type="a(iiay)" access="read"/>
<property name="AttentionMovieName" type="s" access="read"/><property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
<property name="ItemIsMenu" type="b" access="read"/><property name="Menu" type="o" access="read"/>
<signal name="NewTitle"/><signal name="NewIcon"/><signal name="NewToolTip"/><signal name="NewStatus"><arg type="s"/></signal>
</interface><interface name="com.canonical.dbusmenu">
<property name="Version" type="u" access="read"/><property name="TextDirection" type="s" access="read"/>
<property name="Status" type="s" access="read"/><property name="IconThemePath" type="as" access="read"/>
<method name="GetLayout"><arg type="i" direction="in"/><arg type="i" direction="in"/><arg type="as" direction="in"/><arg type="u" direction="out"/><arg type="(ia{sv}av)" direction="out"/></method>
<method name="GetGroupProperties"><arg type="ai" direction="in"/><arg type="as" direction="in"/><arg type="a(ia{sv})" direction="out"/></method>
<method name="GetProperty"><arg type="i" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="out"/></method>
<method name="Event"><arg type="i" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="in"/><arg type="u" direction="in"/></method>
<method name="EventGroup"><arg type="a(isvu)" direction="in"/><arg type="ai" direction="out"/></method>
<method name="AboutToShow"><arg type="i" direction="in"/><arg type="b" direction="out"/></method>
<method name="AboutToShowGroup"><arg type="ai" direction="in"/><arg type="ai" direction="out"/><arg type="ai" direction="out"/></method>
<signal name="LayoutUpdated"><arg type="u"/><arg type="i"/></signal>
<signal name="ItemsPropertiesUpdated"><arg type="a(ia{sv})"/><arg type="a(ias)"/></signal>
</interface></node>'''


def bridge(status=False):
    return [str(ROOT / 'python/bin/python3'), '-I', '-B', '-c',
            'import sys; from oarbank.desktop import main; sys.exit(main())', '--root', str(ROOT)] + (['--status'] if status else [])


class Coordinator(Gtk.Application):
    def __init__(self):
        super().__init__(application_id='dev.codonic.oarbank.coordinator', flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE)
        self.state = 'Checking coordinator…'
        self.checking = False
        self.hosts = set()
        self.activated = False
        self.preferences = None
        self.revision = 1

    def do_startup(self):
        Gtk.Application.do_startup(self)
        self.hold()
        self.window = Gtk.ApplicationWindow(application=self, title='Oarbank Coordinator')
        self.window.set_default_size(390, 240)
        self.window.set_icon_name('oarbank-coordinator')
        self.window.connect('delete-event', self.close_window)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14, margin=24)
        self.window.add(box)
        title = Gtk.Label(label='Oarbank Coordinator', xalign=0)
        title.set_markup('<b>Oarbank Coordinator</b>'); box.pack_start(title, False, False, 0)
        self.state_label = Gtk.Label(label=self.state, xalign=0); box.pack_start(self.state_label, False, False, 0)
        for title, action in [('Open web app', self.open_web), ('Preferences…', self.show_preferences), ('Quit Oarbank Coordinator', self.quit)]:
            button = Gtk.Button(label=title); button.connect('clicked', lambda _, callback=action: callback()); box.pack_start(button, False, False, 0)
        note = Gtk.Label(label='Quitting this app leaves coordinator services running.', xalign=0, wrap=True)
        box.pack_start(note, False, False, 0)
        self.connection = self.get_dbus_connection()
        node = Gio.DBusNodeInfo.new_for_xml(XML)
        self.connection.register_object('/StatusNotifierItem', node.interfaces[0], self.method, self.property, None)
        self.connection.register_object(MENU_PATH, node.interfaces[1], self.method, self.property, None)
        self.bus_name = f'org.kde.StatusNotifierItem-{os.getpid()}-1'
        self.owner = Gio.bus_own_name_on_connection(self.connection, self.bus_name, Gio.BusNameOwnerFlags.NONE, None, None)
        self.watches = [Gio.bus_watch_name_on_connection(self.connection, name, Gio.BusNameWatcherFlags.NONE, self.host_appeared, self.host_vanished)
                        for name in ('org.kde.StatusNotifierWatcher', 'org.freedesktop.StatusNotifierWatcher')]
        GLib.timeout_add_seconds(30, self.refresh)
        if not args.self_test:
            self.refresh()

    def do_command_line(self, command_line):
        background = '--background' in command_line.get_arguments()
        if self.activated and not background:
            self.open_web()
        self.activated = True
        # Allow hosts to register before showing a fallback; no invisible app.
        GLib.timeout_add(500, self.ensure_window, background)
        if args.self_test:
            GLib.idle_add(self.self_test)
        return 0

    def ensure_window(self, background=False):
        if not self.hosts:
            self.window.set_focus_on_map(not background); self.window.show_all()
            if not background: self.window.present()
        return False

    def close_window(self, *_):
        if self.hosts:
            self.window.hide()
        else:
            self.quit()
        return True

    def host_appeared(self, connection, name, owner):
        interface = name
        def registered(bus, result):
            try:
                bus.call_finish(result)
                self.hosts.add(name); self.window.hide()
            except GLib.Error:
                self.ensure_window(True)
        connection.call(name, '/StatusNotifierWatcher', interface, 'RegisterStatusNotifierItem',
                        GLib.Variant('(s)', (connection.get_unique_name(),)), None, Gio.DBusCallFlags.NONE, 3000, None, registered)

    def host_vanished(self, connection, name):
        self.hosts.discard(name)
        if self.activated: self.ensure_window(True)

    def props(self, ident, names=()):
        labels = {1: 'Oarbank Coordinator', 2: self.state, 4: 'Open web app', 5: 'Preferences…', 7: 'Quit Oarbank Coordinator'}
        if ident in (3, 6): result = {'type': GLib.Variant('s', 'separator')}
        else: result = {'label': GLib.Variant('s', labels.get(ident, '')), 'enabled': GLib.Variant('b', ident in (0, 4, 5, 7)), 'visible': GLib.Variant('b', True)}
        if ident == 0: result['children-display'] = GLib.Variant('s', 'submenu')
        return {key: value for key, value in result.items() if not names or key in names}

    def layout(self, parent, depth, names):
        children = [GLib.Variant('(ia{sv}av)', (i, self.props(i, names), [])) for i in range(1, 8)] if parent == 0 and depth != 0 else []
        return (parent, self.props(parent, names), children)

    def action(self, ident, event):
        if event == 'clicked':
            callback = {4: self.open_web, 5: self.show_preferences, 7: self.quit}.get(ident)
            if callback: GLib.idle_add(lambda: (callback(), False)[1])

    def method(self, connection, sender, path, interface, method, parameters, invocation):
        values = parameters.unpack()
        if interface == SNI:
            if method in ('Activate', 'SecondaryActivate', 'ContextMenu'): self.show_preferences() if method == 'SecondaryActivate' else self.show_controls()
            reply = GLib.Variant('()', ())
        elif method == 'GetLayout': reply = GLib.Variant('(u(ia{sv}av))', (self.revision, self.layout(*values)))
        elif method == 'GetGroupProperties': reply = GLib.Variant('(a(ia{sv}))', ([(i, self.props(i, values[1])) for i in values[0] or range(8)],))
        elif method == 'GetProperty': reply = GLib.Variant('(v)', (self.props(values[0]).get(values[1], GLib.Variant('s', '')),))
        elif method == 'AboutToShow': self.refresh(); reply = GLib.Variant('(b)', (False,))
        elif method == 'AboutToShowGroup': self.refresh(); reply = GLib.Variant('(aiai)', ([], []))
        elif method == 'Event': self.action(values[0], values[1]); reply = GLib.Variant('()', ())
        elif method == 'EventGroup':
            for ident, event, _, _ in values[0]: self.action(ident, event)
            reply = GLib.Variant('(ai)', ([],))
        else:
            invocation.return_dbus_error('org.freedesktop.DBus.Error.UnknownMethod', 'Unknown method'); return
        invocation.return_value(reply)

    def property(self, connection, sender, path, interface, name):
        if interface == MENU:
            return {'Version': GLib.Variant('u', 3), 'TextDirection': GLib.Variant('s', 'ltr'), 'Status': GLib.Variant('s', 'normal'), 'IconThemePath': GLib.Variant('as', [])}.get(name)
        properties = {'Category': GLib.Variant('s', 'ApplicationStatus'), 'Id': GLib.Variant('s', 'oarbank-coordinator'),
                      'Title': GLib.Variant('s', 'Oarbank Coordinator'), 'Status': GLib.Variant('s', 'Active'),
                      'WindowId': GLib.Variant('u', 0), 'IconName': GLib.Variant('s', 'oarbank-coordinator'),
                      'IconThemePath': GLib.Variant('s', '/usr/share/icons/hicolor/scalable/apps'),
                      'ItemIsMenu': GLib.Variant('b', True), 'Menu': GLib.Variant('o', MENU_PATH),
                      'ToolTip': GLib.Variant('(sa(iiay)ss)', ('oarbank-coordinator', [], 'Oarbank Coordinator', self.state))}
        if name.endswith('Pixmap'): return GLib.Variant('a(iiay)', [])
        return properties.get(name, GLib.Variant('s', ''))

    def show_controls(self):
        self.window.show_all(); self.window.present()

    def refresh(self):
        if not self.checking:
            self.checking = True
            def worker():
                state = 'Status unavailable'
                try:
                    result = subprocess.run(bridge(True), capture_output=True, text=True, timeout=8, check=True)
                    status = json.loads(result.stdout)
                    state = ('Coordinator online' if status['online'] else 'Coordinator offline') if status['configured'] else ('Finish authenticator setup' if status['pending'] else 'Setup needed')
                except (OSError, ValueError, subprocess.SubprocessError): pass
                GLib.idle_add(self.update, state)
            threading.Thread(target=worker, daemon=True).start()
        return True

    def update(self, state):
        self.checking = False; self.state = state; self.state_label.set_text(state); self.revision += 1
        self.connection.emit_signal(None, MENU_PATH, MENU, 'LayoutUpdated', GLib.Variant('(ui)', (self.revision, 0)))
        self.connection.emit_signal(None, '/StatusNotifierItem', SNI, 'NewToolTip', None)
        return False

    def open_web(self):
        try: subprocess.Popen(bridge(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as error: self.error('Could not open the coordinator', str(error))

    def error(self, title, message):
        dialog = Gtk.MessageDialog(transient_for=self.preferences or self.window, modal=True, message_type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.CLOSE, text=title)
        dialog.format_secondary_text(message); dialog.run(); dialog.destroy()

    def show_preferences(self):
        if self.preferences is None:
            window = Gtk.ApplicationWindow(application=self, title='Oarbank Coordinator Preferences'); window.set_default_size(440, 230)
            window.set_icon_name('oarbank-coordinator'); window.connect('delete-event', lambda *_: (window.hide(), True)[1])
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14, margin=24); window.add(box)
            title = Gtk.Label(xalign=0); title.set_markup('<b>Oarbank Coordinator</b>'); box.pack_start(title, False, False, 0)
            self.automatic = Gtk.CheckButton(label='Start automatically at sign-in')
            self.automatic.set_active(autostart.enabled()); self.automatic.connect('toggled', self.toggle_startup); box.pack_start(self.automatic, False, False, 0)
            for text in ['Applies to your account. You can also manage this in your desktop startup settings.', 'Quitting this app leaves coordinator services running. Automatic startup opens the tray app quietly.']:
                box.pack_start(Gtk.Label(label=text, xalign=0, wrap=True), False, False, 0)
            self.preferences = window
        self.preferences.show_all(); self.preferences.present()
        self.automatic.handler_block_by_func(self.toggle_startup)
        self.automatic.set_active(autostart.enabled())
        self.automatic.handler_unblock_by_func(self.toggle_startup)

    def toggle_startup(self, button):
        try: autostart.set_enabled(button.get_active())
        except OSError as error:
            self.error('Could not change automatic startup', str(error))
            button.handler_block_by_func(self.toggle_startup); button.set_active(autostart.enabled()); button.handler_unblock_by_func(self.toggle_startup)

    def self_test(self):
        try:
            assert not autostart.enabled()
            autostart.set_enabled(True); assert autostart.enabled()
            autostart.set_enabled(False); assert not autostart.enabled()
            self.show_preferences(); assert not self.automatic.get_active()
            layout = GLib.Variant('(u(ia{sv}av))', (self.revision, self.layout(0, -1, []))).unpack()
            assert layout[1][1]['enabled'] is True
            assert len(layout[1][2]) == 7
            assert layout[1][2][3][1]['label'] == 'Open web app'
            assert self.property(None, None, None, SNI, 'Menu').unpack() == MENU_PATH
            print('Native GTK controls, SNI menu and per-user autostart round-trip passed.', flush=True)
        except Exception:
            import traceback; traceback.print_exc(); os._exit(1)
        self.quit(); return False


GLib.set_prgname('oarbank-coordinator')
raise SystemExit(Coordinator().run([sys.argv[0]] + (['--background'] if args.background else [])))
