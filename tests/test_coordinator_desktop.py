"""The desktop bridge cannot create accounts/services or expose enrollment secrets."""
import json
from pathlib import Path
import pytest
from oarbank import desktop, setup
from oarbank.platform import files
from test_coordinator_setup import wizard


def test_status_is_read_only_and_pending_setup_takes_precedence(tmp_path, monkeypatch):
    monkeypatch.setattr(desktop.httpx, 'Client', lambda **kw: pytest.fail('No health probe before setup'))
    assert not desktop.status(tmp_path)['configured']
    assert not list(tmp_path.iterdir())
    (tmp_path / 'oarbank.sqlite3').write_text('existing account')
    (tmp_path / 'setup.pending.json').write_text('{"totp_secret":"must-not-be-read"}')
    state = desktop.status(tmp_path)
    assert not state['configured'] and state['pending'] and not state['online']
    assert 'must-not-be-read' not in json.dumps(state)
    assert state['console'].startswith('http://127.0.0.1:')


def test_health_uses_loopback_without_proxies_or_redirects(tmp_path, monkeypatch):
    (tmp_path / 'setup.complete.json').write_text('completed')
    class Client:
        def __init__(self, **kw): assert kw == {'trust_env': False, 'follow_redirects': False}
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url, **kw):
            assert url == 'http://127.0.0.1:7400/healthz' and kw['timeout'] == 2
            return desktop.httpx.Response(200,json={'ok':True})
    monkeypatch.setattr(desktop.C,'CONSOLE_PORT',7400)
    monkeypatch.setattr(desktop.httpx,'Client',Client)
    assert desktop.status(tmp_path)['online']


def test_open_existing_web_app_does_not_run_setup(tmp_path, monkeypatch):
    (tmp_path / 'oarbank-coordinator.json').write_text('{"format":1}')
    monkeypatch.setattr(desktop, 'status', lambda: {'configured':True,'console':'http://127.0.0.1:7400/login'})
    monkeypatch.setattr(setup,'main',lambda *_:pytest.fail('Should not start setup'))
    opened=[]
    monkeypatch.setattr(desktop.webbrowser,'open',opened.append)
    assert desktop.main(['--root',str(tmp_path)]) == 0
    assert opened == ['http://127.0.0.1:7400/login']


@pytest.mark.parametrize('pending', [False, True])
def test_protected_service_state_uses_only_loopback_setup_flags(monkeypatch, pending):
    def denied(*args):
        raise PermissionError('Service data is private')
    monkeypatch.setattr(desktop, 'setup_state', denied)
    class Client:
        def __init__(self, **kw): assert kw == {'trust_env': False, 'follow_redirects': False}
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url, **kw):
            return desktop.httpx.Response(200, json={'ok': True, 'coordinator_setup': {'configured': not pending, 'pending': pending}})
    monkeypatch.setattr(desktop.httpx, 'Client', Client)
    state = desktop.status()
    assert state['configured'] is (not pending) and state['pending'] is pending
    assert state['online'] is (not pending)


def test_running_wizard_reopens_only_private_authenticated_loopback(wizard):
    # Reuse real HTTP guards: bogus capabilities must not become browser links.
    from test_coordinator_setup import serving
    active = wizard.home / 'setup.active.json'
    with serving(wizard) as server:
        assert setup.running_setup(wizard.home) is None
        files.write_private(active,json.dumps({'origin':server.origin,'capability':wizard.capability}))
        assert setup.running_setup(wizard.home) == server.origin + '/#' + wizard.capability
        files.write_private(active,json.dumps({'origin':server.origin,'capability':'x'*43}))
        assert setup.running_setup(wizard.home) is None
    files.write_private(active,json.dumps({'origin':'https://evil.example','capability':'x'*43}))
    assert setup.running_setup(wizard.home) is None
    files.write_private(active,'invalid json')
    assert setup.running_setup(wizard.home) is None
