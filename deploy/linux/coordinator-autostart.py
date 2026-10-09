"""The desktop preference owns only this user's Oarbank autostart entry."""
import configparser
import os
from pathlib import Path
import tempfile

ENTRY = '[Desktop Entry]\nType=Application\nName=Oarbank Coordinator\nExec=/usr/bin/oarbank-coordinator --background\nIcon=oarbank-coordinator\nTerminal=false\nX-OarbankManaged=true\n'


def entry_path():
    root = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    if not root.is_absolute():
        root = Path.home() / '.config'  # The XDG specification requires absolute paths.
    return root / 'autostart/oarbank-coordinator.desktop'


def managed(path):
    config = configparser.ConfigParser(interpolation=None)
    try:
        config.read_string(path.read_text())
        entry = config['Desktop Entry']
        if entry.get('X-OarbankManaged') == 'true' and entry.get('Exec') == '/usr/bin/oarbank-coordinator --background':
            return entry
    except (OSError, KeyError, configparser.Error):
        pass
    return None


def enabled():
    path = entry_path()
    if path.is_symlink() or not path.is_file():
        return False
    entry = managed(path)
    return entry is not None and entry.get('Hidden', 'false') != 'true' and entry.get('X-GNOME-Autostart-enabled', 'true') != 'false'


def set_enabled(value):
    path = entry_path()
    if path.is_symlink() or (path.exists() and managed(path) is None):
        raise OSError('A custom Oarbank autostart entry already exists. Manage it in your desktop startup settings.')
    if not value:
        path.unlink(missing_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.oarbank-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(ENTRY)
        os.chmod(name, 0o644)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)
