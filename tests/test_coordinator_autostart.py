"""Native Linux preference lifecycle; never touches the user's actual startup."""
import importlib.util
import os
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location('autostart', Path(__file__).parents[1] / 'deploy/linux/coordinator-autostart.py')
autostart = importlib.util.module_from_spec(spec)
spec.loader.exec_module(autostart)


def test_startup_is_opt_in_per_user_and_round_trips(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
    assert not autostart.enabled() and not list(tmp_path.iterdir())
    autostart.set_enabled(True)
    entry=autostart.entry_path()
    assert autostart.enabled()
    if os.name != "nt":
        assert entry.stat().st_mode & 0o777 == 0o644
    assert '--background' in entry.read_text()
    autostart.set_enabled(False)
    assert not autostart.enabled() and not entry.exists()


@pytest.mark.parametrize('symlink',[False,True])
def test_custom_entry_is_never_overwritten_or_deleted(tmp_path, monkeypatch, symlink):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
    entry=autostart.entry_path();entry.parent.mkdir()
    target=tmp_path/'custom';target.write_text('custom startup')
    if symlink: entry.symlink_to(target)
    else: entry.write_text('custom startup')
    for enabled in (True,False):
        with pytest.raises(OSError,match='custom'):autostart.set_enabled(enabled)
    assert target.read_text() == 'custom startup' and entry.read_text() == 'custom startup'


def test_desktop_startup_disable_is_reflected_and_user_can_reenable(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
    autostart.set_enabled(True)
    entry = autostart.entry_path()
    entry.write_text(entry.read_text() + 'Hidden=true\n')
    assert not autostart.enabled()
    autostart.set_enabled(True)
    assert autostart.enabled()
