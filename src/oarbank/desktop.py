"""Read-only desktop status. Opening the web app never starts/reconfigures services.

The native frontends run as the signed-in user; only their explicit setup action
invokes the existing first-run wizard (and Windows elevation broker), and only the
explicit move action (`--migrate`) moves this account's per-user coordinator of an
earlier release to the system service (sysmigrate.py).
"""
import argparse
import json
import os
import sys
from pathlib import Path
import webbrowser

import httpx

from . import __version__
from .coordinator import config as C


def setup_state(home=None):
    home = Path(home or C.HOME)
    from .setup import journal_dir
    journal = journal_dir(home)
    pending = (journal / 'setup.pending.json').exists()
    if pending and journal != home:
        return {'configured': False, 'pending': True}
    configured = not pending and any((home / name).exists() for name in
        ('setup.complete.json', 'oarbank.sqlite3', 'admin.token', 'console.secret'))
    return {'configured': configured, 'pending': pending}


def status(home=None):
    try:
        local = setup_state(home)
    except PermissionError:
        # Windows service data deliberately excludes ordinary desktop users.
        # The loopback console reports only these two non-secret booleans.
        local = None
    configured = local['configured'] if local else False
    pending = local['pending'] if local else False
    console = f'http://127.0.0.1:{C.CONSOLE_PORT}/login'
    online = False
    if configured or local is None:
        try:
            with httpx.Client(trust_env=False, follow_redirects=False) as client:
                response = client.get(console.rsplit('/', 1)[0] + '/healthz', timeout=2)
                payload = response.json() if response.status_code == 200 else {}
                online = payload.get('ok') is True and payload.get('coordinator_ok', True) is True
                remote = payload.get('coordinator_setup')
                if local is None and isinstance(remote, dict) and all(type(remote.get(k)) is bool for k in ('configured', 'pending')):
                    pending = remote['pending']
                    configured = remote['configured'] and not pending
        except (httpx.HTTPError, ValueError):
            pass
    return {'configured': configured, 'pending': pending, 'online': online and configured,
            'console': console, 'version': __version__, **service_form()}


def service_form():
    """How this Mac's (or Linux machine's) coordinator is installed, from files anyone may read: `system` when the
    installer recorded the system services, `per_user` when this account still has an earlier release's per-user
    coordinator (the app then offers to move it), and the migration's state when one is recorded."""
    if sys.platform == 'win32':
        return {'form': 'system', 'per_user': False, 'migration': None}
    from . import paths, sysmigrate
    layout = sysmigrate.Layout()
    import getpass
    try:
        mine = sysmigrate.find_installs(layout, [(getpass.getuser(), os.getuid(), os.getgid(), Path.home())])
    except sysmigrate.MigrationError:
        mine = []
    record = sysmigrate.read_record(layout) or {}
    form = 'per-user' if mine else ('system' if paths.service_record().exists() else 'none')
    return {'form': form, 'per_user': bool(mine), 'migration': record.get('state'),
            'migration_detail': (record.get('steps') or [{}])[-1].get('detail')}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Local coordinator desktop status and web app launcher.')
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--status', action='store_true')
    parser.add_argument('--migrate', action='store_true',
                        help='move this account\'s per-user coordinator to the system service (asks for an administrator)')
    args = parser.parse_args(argv)
    manifest = json.loads((args.root / 'oarbank-coordinator.json').read_text())
    if manifest.get('format') != 1:
        parser.error('Unknown coordinator build format.')
    if args.migrate:
        from . import sysmigrate
        try:
            return sysmigrate.run_as_person()
        except sysmigrate.MigrationError as e:
            print(f'Could not move the coordinator: {e}', flush=True)
            return 1
    state = status()
    if args.status:
        print(json.dumps(state), flush=True)
        return 0
    if state['configured']:
        # Browser login still requires the account's authentication factors.
        webbrowser.open(state['console'])
        return 0
    from .setup import main as setup
    return setup(['--root', str(args.root)])
