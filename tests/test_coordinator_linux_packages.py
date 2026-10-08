"""Linux coordinator packaging/removal; stdlib tests, no host services or installs.

Run directly with python3 tests/test_coordinator_linux_packages.py, or with pytest.
"""
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

# Guard collection before coordinator-remove.py imports the POSIX-only pwd
# module. Keep direct execution and unittest discovery independent of pytest.
if sys.platform == "win32":
    reason = "Linux coordinator packaging/removal tests require POSIX"
    if __name__ == "__main__":
        @unittest.skip(reason)
        class WindowsPlatformTests(unittest.TestCase):
            def test_linux_coordinator_packages(self):
                pass

        unittest.main()
    if "pytest" in sys.modules:
        import pytest

        pytest.skip(reason, allow_module_level=True)
    raise unittest.SkipTest(reason)

REPO = Path(__file__).resolve().parents[1]
DEPLOY = REPO / "deploy/linux"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), DEPLOY / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stage = load_script("coordinator-stage")
remove = load_script("coordinator-remove")


def make_archive(path, platform="linux-amd64", version="2.5.0", omit=None, extra=None):
    with tarfile.open(path, "w:gz") as tf:
        def add(name, data, mode=0o755):
            if name == omit:
                return
            info = tarfile.TarInfo(name)
            info.mode, info.size = mode, len(data)
            tf.addfile(info, io.BytesIO(data))
        add("oarbank-coordinator.json", json.dumps({"format": 1, "version": version, "platform": platform,
            "exec": ["bin/oarbankd"], "console": ["bin/oarbank-console"]}).encode(), 0o644)
        for name in ("oarbankd", "oarbank-console", "oarbank", "uv", "oarbank-sandbox", "oarbank-setup"):
            # If staging ever runs the build's foreign executable, it fails.
            add("bin/" + name, b"#!/bin/sh\nexit 91\n")
        add("python/bin/python3.12", b"foreign interpreter\n")
        info = tarfile.TarInfo("python/bin/python3")
        info.type, info.linkname = tarfile.SYMTYPE, "python3.12"
        tf.addfile(info)
        add("python/lib/resource.dat", b"runtime resource", 0o644)
        if extra:
            tf.addfile(*extra)


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="oarbank package tests ")
        self.base = Path(self.tmp.name)
        self.archive = self.base / "build.tar.gz"
        self.work = self.base / "work"
        self.work.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_stage_preserves_archive_manifest_links_modes_and_bundles_helper(self):
        make_archive(self.archive)
        original = self.archive.read_bytes()
        stage.stage(REPO, self.archive, "2.5.0", self.work)
        self.assertEqual(self.archive.read_bytes(), original)
        root = self.work / "coordinator"
        with tarfile.open(self.archive) as tf:
            self.assertEqual((root / "oarbank-coordinator.json").read_bytes(), tf.extractfile("oarbank-coordinator.json").read())
        self.assertEqual((root / "python/bin/python3").readlink(), Path("python3.12"))
        self.assertEqual((root / "bin/oarbank-setup").stat().st_mode & 0o777, 0o755)
        self.assertEqual((root / "python/lib/resource.dat").stat().st_mode & 0o777, 0o644)
        self.assertEqual((root / "install-oarbankd.sh").read_bytes(), (REPO / "deploy/oarbankd/install-oarbankd.sh").read_bytes())
        config = (self.work / "nfpm.yaml").read_text()
        self.assertIn('arch: "amd64"', config)
        self.assertIn(json.dumps(str(root)), config)
        self.assertNotIn("${", config)
        self.assertNotIn("postinstall:", config)
        self.assertIn("preremove:", config)
        self.assertIn("dst: /usr/bin/oarbank-setup\n    type: symlink", config)
        desktop = (DEPLOY / "coordinator-desktop.desktop").read_text()
        self.assertIn("Name=Oarbank Coordinator\n", desktop)
        self.assertIn("Exec=/opt/oarbank/coordinator/bin/oarbank-setup\n", desktop)
        self.assertIn("Terminal=false\n", desktop)

    def test_arm64_is_selected_from_manifest(self):
        make_archive(self.archive, platform="linux-arm64")
        stage.stage(REPO, self.archive, "2.5.0", self.work)
        self.assertEqual((self.work / "arch").read_text(), "arm64\n")

    def test_rejects_wrong_platform_version_and_missing_wizard(self):
        cases = ({"platform": "darwin-arm64"}, {"version": "2.4.0"}, {"omit": "bin/oarbank-setup"})
        for index, options in enumerate(cases):
            with self.subTest(options=options):
                work = self.base / str(index)
                work.mkdir()
                make_archive(self.archive, **options)
                with self.assertRaises(ValueError):
                    stage.stage(REPO, self.archive, "2.5.0", work)

    def test_rejects_traversal_special_files_and_escaping_links(self):
        for index, kind in enumerate(("traversal", "symlink", "nested", "fifo", "hardlink", "chain")):
            with self.subTest(kind=kind):
                info = tarfile.TarInfo("../escaped" if kind == "traversal" else "bad")
                if kind in ("symlink", "nested", "chain"):
                    info.type = tarfile.SYMTYPE
                    info.linkname = "/etc/passwd" if kind == "symlink" else "bin" if kind == "nested" else "bad"
                elif kind == "fifo":
                    info.type = tarfile.FIFOTYPE
                elif kind == "hardlink":
                    info.type, info.linkname = tarfile.LNKTYPE, "bin/uv"
                make_archive(self.archive, extra=(info,))
                if kind == "nested":
                    # Re-create with a symlink in an ancestor of existing files.
                    info.name = "bin"
                    make_archive(self.archive, extra=(info,))
                work = self.base / str(index)
                work.mkdir()
                with self.assertRaises((ValueError, RuntimeError, OSError)):
                    stage.stage(REPO, self.archive, "2.5.0", work)
                self.assertFalse((self.base / "escaped").exists())

    def test_wrapper_invokes_both_packagers_and_keeps_archive_sums(self):
        repo = self.base / "isolated repo"
        (repo / "scripts").mkdir(parents=True)
        (repo / "deploy/oarbankd").mkdir(parents=True)
        shutil.copytree(DEPLOY, repo / "deploy/linux")
        shutil.copy2(REPO / "scripts/package-coordinator-linux.sh", repo / "scripts")
        (repo / "deploy/oarbankd/install-oarbankd.sh").write_text("#!/bin/sh\n# installed helper\n")
        (repo / "pyproject.toml").write_text('version = "2.5.0"\n')
        (repo / "dist").mkdir()
        archive = repo / "dist/oarbank-coordinator-2.5.0-linux-arm64.tar.gz"
        make_archive(archive, platform="linux-arm64")
        archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        sums = repo / "dist/SHA256SUMS-coordinator-2.5.0-linux-arm64"
        sums.write_text("original archive sums\n")
        bins = self.base / "bin"
        bins.mkdir()
        (bins / "python3").symlink_to(sys.executable)
        nfpm = bins / "nfpm"
        nfpm.write_text("#!" + sys.executable + "\n"
            "import json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['PACKAGE_TEST_CALLS'], 'a') as f: f.write(json.dumps(args) + '\\n')\n"
            "pathlib.Path(args[args.index('--target')+1]).write_text(args[args.index('--packager')+1])\n")
        nfpm.chmod(0o755)
        calls = self.base / "calls"
        env = dict(os.environ, PATH=str(bins) + os.pathsep + os.environ["PATH"], PACKAGE_TEST_CALLS=str(calls))
        result = subprocess.run(["bash", str(repo / "scripts/package-coordinator-linux.sh"), "2.5.0", str(archive)],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        invocations = [json.loads(line) for line in calls.read_text().splitlines()]
        self.assertEqual([args[args.index("--packager") + 1] for args in invocations], ["deb", "rpm"])
        for fmt in ("deb", "rpm"):
            self.assertEqual((repo / ("dist/oarbank-coordinator-2.5.0-linux-arm64." + fmt)).read_text(), fmt)
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), archive_hash)
        self.assertEqual(sums.read_text(), "original archive sums\n")
        package_sums = (repo / "dist/SHA256SUMS-coordinator-packages-2.5.0-linux-arm64").read_text()
        self.assertIn(hashlib.sha256(b"deb").hexdigest(), package_sums)
        self.assertIn(hashlib.sha256(b"rpm").hexdigest(), package_sums)
        self.assertFalse(Path(invocations[0][invocations[0].index("--config") + 1]).exists())

    def test_upgrade_hooks_exit_without_executing_services(self):
        for arg in ("upgrade", "failed-upgrade", "1", "2", "10", "abort-upgrade"):
            with self.subTest(arg=arg):
                result = subprocess.run(["sh", str(DEPLOY / "coordinator-preremove.sh"), arg], capture_output=True)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_removal_hook_propagates_cleanup_failure(self):
        # Substitute an inert interpreter only in a temporary hook copy.
        interpreter = self.base / "failed-cleanup"
        interpreter.write_text("#!/bin/sh\nexit 17\n")
        interpreter.chmod(0o755)
        hook = self.base / "preremove.sh"
        hook.write_text((DEPLOY / "coordinator-preremove.sh").read_text().replace(
            "/opt/oarbank/coordinator/python/bin/python3", json.dumps(str(interpreter))))
        for arg in ("remove", "deconfigure", "0"):
            with self.subTest(arg=arg):
                result = subprocess.run(["sh", str(hook), arg], capture_output=True)
                self.assertEqual(result.returncode, 17)

    @unittest.skipUnless(shutil.which("nfpm"), "nFPM is unavailable; no tools are installed by these tests")
    def test_real_nfpm_builds_both_formats_without_installing(self):
        make_archive(self.archive)
        stage.stage(REPO, self.archive, "2.5.0", self.work)
        for fmt, magic in (("deb", b"!<arch>\n"), ("rpm", b"\xed\xab\xee\xdb")):
            with self.subTest(format=fmt):
                output = self.base / ("coordinator." + fmt)
                result = subprocess.run(["nfpm", "package", "--config", str(self.work / "nfpm.yaml"),
                                         "--packager", fmt, "--target", str(output)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(output.read_bytes().startswith(magic))


class RemovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.home = self.base / "alice home"
        self.home.mkdir()
        self.runtime = self.base / "runtime"
        self.units = self.home / ".config/systemd/user"
        self.units.mkdir(parents=True)
        self.unit = self.units / remove.UNITS[0]

    def tearDown(self):
        self.tmp.cleanup()

    def write_unit(self, root=remove.ROOT):
        self.unit.write_text('[Service]\nExecStart="' + root + '/bin/oarbankd" --agent-bind localhost\nRestart=on-failure\n')
        wants = self.units / "default.target.wants"
        wants.mkdir(exist_ok=True)
        (wants / self.unit.name).symlink_to("../" + self.unit.name)

    def manager(self):
        (self.runtime / "systemd").mkdir(parents=True)
        (self.runtime / "systemd/private").touch()

    def test_offline_user_disabled_without_root_home_or_data_deletion(self):
        self.write_unit()
        data = self.home / ".local/share/oarbank/coordinator/db.sqlite"
        data.parent.mkdir(parents=True)
        data.write_text("keep keys and data")
        with patch.object(remove, "systemctl") as ctl, patch.dict(os.environ, HOME="/root"):
            remove.cleanup_user(self.home, self.runtime)
        ctl.assert_not_called()
        self.assertFalse(self.unit.exists())
        self.assertEqual(list((self.units / "default.target.wants").iterdir()), [])
        self.assertEqual(data.read_text(), "keep keys and data")

    def test_other_archive_installation_is_preserved(self):
        self.write_unit(str(self.home / "coordinator-app/current"))
        with patch.object(remove, "systemctl") as ctl:
            remove.cleanup_user(self.home, self.runtime)
        self.assertTrue(self.unit.exists())
        self.assertTrue((self.units / "default.target.wants" / self.unit.name).is_symlink())
        ctl.assert_not_called()

    def test_registry_discovers_custom_offline_xdg_path(self):
        self.units = self.base / "custom config/systemd/user"
        self.units.mkdir(parents=True)
        self.unit = self.units / remove.UNITS[0]
        self.write_unit()
        registry = self.home / ".local/share/oarbank/coordinator-package.json"
        registry.parent.mkdir(parents=True)
        registry.write_text(json.dumps({"format": 1, "root": remove.ROOT, "unit_dir": str(self.units)}))
        remove.cleanup_user(self.home, self.runtime)
        self.assertFalse(self.unit.exists())
        self.assertFalse(registry.exists())

    def test_active_services_stop_before_unlink_and_reload(self):
        self.manager()
        self.write_unit()
        calls = []
        def ctl(*args):
            calls.append(args)
            if args == ("show", "--property=UnitPath", "--value"):
                return json.dumps(str(self.units))
            if args[0] == "show":
                unit = args[1]
                if unit == self.unit.name and self.unit.exists():
                    return "LoadState=loaded\nFragmentPath=" + str(self.unit) + '\nExecStart={ path=' + remove.ROOT + '/bin/oarbankd ; }'
                return "LoadState=not-found\nExecStart="
            if args[0] == "stop":
                self.assertTrue(self.unit.exists())
            if args[0] == "daemon-reload":
                self.assertFalse(self.unit.exists())
            return ""
        with patch.object(remove, "systemctl", side_effect=ctl):
            remove.cleanup_user(self.home, self.runtime)
        self.assertIn(("stop", self.unit.name), calls)
        self.assertIn(("daemon-reload",), calls)

    def test_failed_stop_blocks_cleanup_leaving_executable_references_intact(self):
        self.manager()
        self.write_unit()
        def ctl(*args):
            if args[0] == "stop":
                raise RuntimeError("user bus unreachable")
            if "--property=UnitPath" in args:
                return ""
            return "LoadState=loaded\nExecStart=" + remove.ROOT + "/bin/oarbankd"
        with patch.object(remove, "systemctl", side_effect=ctl):
            with self.assertRaisesRegex(RuntimeError, "unreachable"):
                remove.cleanup_user(self.home, self.runtime)
        self.assertTrue(self.unit.exists())

    def test_malformed_registry_is_not_silently_ignored(self):
        registry = self.home / ".local/share/oarbank/coordinator-package.json"
        registry.parent.mkdir(parents=True)
        registry.write_text(json.dumps({"format": 1, "root": remove.ROOT, "unit_dir": "relative"}))
        with self.assertRaisesRegex(ValueError, "invalid"):
            remove.cleanup_user(self.home, self.runtime)

    def test_matching_dropin_and_enablement_alias_are_removed(self):
        self.write_unit("/other/build")
        dropins = self.units / (self.unit.name + ".d")
        dropins.mkdir()
        override = dropins / "coordinator.conf"
        override.write_text("[Service]\nExecStart=\nExecStart=" + remove.ROOT + "/bin/oarbankd\n")
        # Disabling a package override should also remove links enabling the
        # affected base unit, even when its own ExecStart names another build.
        remove.cleanup_user(self.home, self.runtime)
        self.assertFalse(override.exists())
        self.assertTrue(self.unit.exists())
        self.assertEqual(list((self.units / "default.target.wants").iterdir()), [])

    def test_systemctl_errors_and_timeout_are_not_swallowed(self):
        failure = SimpleNamespace(returncode=1, stdout="", stderr="cannot connect to user bus")
        with patch.object(remove.subprocess, "run", return_value=failure):
            with self.assertRaisesRegex(RuntimeError, "cannot connect"):
                remove.systemctl("stop", remove.UNITS[0])
        with patch.object(remove.subprocess, "run", side_effect=subprocess.TimeoutExpired("systemctl", 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                remove.systemctl("stop", remove.UNITS[0])

    def test_missing_unit_is_normal_for_an_unrelated_active_user(self):
        absent = SimpleNamespace(returncode=1, stdout="LoadState=not-found\nExecStart=", stderr="")
        with patch.object(remove.subprocess, "run", return_value=absent):
            self.assertIn("LoadState=not-found", remove.systemctl("show", remove.UNITS[0], "--property=LoadState,ExecStart"))

    def test_package_path_in_description_does_not_select_unrelated_service(self):
        self.assertFalse(remove.references_package("Description=" + remove.ROOT + "/bin/oarbankd\nExecStart=/other/bin/oarbankd"))
        self.assertFalse(remove.references_package("ExecStart=" + remove.ROOT + "/bin/oarbankd-other"))

    def test_loaded_systemctl_execstart_structures_match_path_and_closing_brace(self):
        for binary in ("oarbankd", "oarbank-console"):
            path = remove.ROOT + "/bin/" + binary
            for value in ("ExecStart={ path=" + path + " ; argv[]=" + path
                          + " --agent-bind localhost ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a]"
                          + " ; pid=0 ; code=(null) ; status=0/0 }",
                          "ExecStart={ path=" + path + "}",
                          "ExecStart={ path=" + path + ";argv[]=" + path + "}"):
                with self.subTest(value=value):
                    self.assertTrue(remove.references_package(value))
        self.assertFalse(remove.references_package("ExecStart={ path=/other/build/bin/oarbankd ; argv[]=/other/build/bin/oarbankd }"))

    def test_dispatch_drops_privileges_and_sets_nss_home_not_caller_home(self):
        account = SimpleNamespace(pw_name="alice", pw_dir=str(self.home), pw_uid=1007, pw_gid=1008)
        with patch.object(remove.os, "geteuid", return_value=0), patch.object(remove.pwd, "getpwall", return_value=[account]), \
             patch.object(remove.os, "fork", return_value=0), patch.object(remove.os, "initgroups") as groups, \
             patch.object(remove.os, "setgid") as gid, patch.object(remove.os, "setuid") as uid, \
             patch.object(remove.os, "chdir"), patch.object(remove.os, "_exit", side_effect=SystemExit) as exit_, \
             patch.dict(os.environ, {"HOME": "/root", "XDG_CONFIG_HOME": "/root/.config"}), \
             patch.object(remove, "cleanup_user") as cleanup:
            with self.assertRaises(SystemExit):
                remove.main()
            self.assertEqual(os.environ["HOME"], str(self.home))
            self.assertNotIn("XDG_CONFIG_HOME", os.environ)
            groups.assert_called_once_with("alice", 1008)
            gid.assert_called_once_with(1008)
            uid.assert_called_once_with(1007)
            cleanup.assert_called_once_with(self.home, Path("/run/user/1007"))
            exit_.assert_called_once_with(0)

    def test_account_cleanup_failure_returns_nonzero_to_package_manager(self):
        account = SimpleNamespace(pw_name="alice", pw_dir=str(self.home), pw_uid=1007, pw_gid=1008)
        with patch.object(remove.os, "geteuid", return_value=0), patch.object(remove.pwd, "getpwall", return_value=[account]), \
             patch.object(remove.os, "fork", return_value=45), patch.object(remove.os, "waitpid", return_value=(45, 256)), \
             patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(remove.main(), 1)
            self.assertIn("removal blocked", err.getvalue())

    def test_active_user_lookup_works_when_nss_enumeration_is_disabled(self):
        runtime_root = self.base / "run/user"
        (runtime_root / "1007/systemd").mkdir(parents=True)
        (runtime_root / "1007/systemd/private").touch()
        account = SimpleNamespace(pw_name="alice", pw_dir=str(self.home), pw_uid=1007, pw_gid=1008)
        with patch.object(remove.pwd, "getpwall", return_value=[]), \
             patch.object(remove.pwd, "getpwuid", return_value=account) as lookup:
            self.assertEqual(remove.accounts_to_clean(runtime_root), [account])
            lookup.assert_called_once_with(1007)
        with patch.object(remove.pwd, "getpwall", return_value=[]), \
             patch.object(remove.pwd, "getpwuid", side_effect=KeyError):
            with self.assertRaisesRegex(RuntimeError, "no NSS account"):
                remove.accounts_to_clean(runtime_root)


if __name__ == "__main__":
    unittest.main()
