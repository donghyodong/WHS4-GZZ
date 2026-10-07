"""The Launcher must not silently omit InputSignature when YARA is unavailable."""

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


LAUNCHER_DIR = Path(__file__).resolve().parents[1]
if str(LAUNCHER_DIR) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_DIR))

import launcher_heartbeat  # noqa: E402
import main as launcher_main  # noqa: E402
import modules  # noqa: E402
import process_manager  # noqa: E402


class InputSignatureRuntimeTests(unittest.TestCase):
    def test_missing_yara_reports_interpreter_and_install_action(self):
        with mock.patch.object(modules, "import_module",
                               side_effect=ModuleNotFoundError("No module named 'yara'")):
            message = modules.yara_runtime_error()
        self.assertIn("ModuleNotFoundError", message)
        self.assertIn(sys.executable, message)
        self.assertIn("client/LocalGuard/input_signature/requirements.txt", message)

    def test_wrong_yara_version_is_a_failure(self):
        with mock.patch.object(modules, "import_module",
                               return_value=SimpleNamespace(__version__="4.5.3")):
            self.assertIn("4.5.3 != 4.5.4", modules.yara_runtime_error())

    def test_pinned_yara_version_is_ready(self):
        with mock.patch.object(modules, "import_module",
                               return_value=SimpleNamespace(__version__="4.5.4")):
            self.assertEqual(modules.yara_runtime_error(), "")

    def test_dependency_failure_is_visible_and_not_spawned(self):
        with mock.patch.object(modules, "yara_runtime_error", return_value="YARA unavailable"):
            scanner = modules.input_signature_module()
        with tempfile.TemporaryDirectory() as directory, (
            mock.patch.object(process_manager, "LOG_DIR", directory)
        ), mock.patch.object(process_manager, "is_admin", return_value=False), (
            mock.patch.object(process_manager.registry, "begin_session")
        ), mock.patch.object(process_manager.registry, "spawn") as spawn:
            manager = process_manager.ProcessManager(
                [scanner], "normal_001", "player_042", 1000.25
            )
            state = manager.states[scanner.name]
            self.assertEqual(state.status, process_manager.FAILED)
            self.assertEqual(state.detail, "YARA unavailable")
            self.assertFalse(manager.start(scanner.name))
            spawn.assert_not_called()
        status, required, pid, details = launcher_heartbeat.component_of(state)
        self.assertEqual((status, required, pid), ("failed", True, None))
        self.assertEqual(details["launcher_status"], process_manager.FAILED)

    def test_dependency_failure_is_shown_before_waiting_for_game(self):
        with mock.patch.object(modules, "yara_runtime_error", return_value="YARA unavailable"):
            scanner = modules.input_signature_module()
        with tempfile.TemporaryDirectory() as directory, (
            mock.patch.object(process_manager, "LOG_DIR", directory)
        ), mock.patch.object(process_manager, "is_admin", return_value=False), (
            mock.patch.object(process_manager.registry, "begin_session")
        ), mock.patch.object(launcher_main, "publish_game_dir", return_value=None), (
            mock.patch.object(launcher_main.ui, "line")
        ) as line:
            manager = process_manager.ProcessManager(
                [scanner], "normal_001", "player_042", 1000.25
            )
            launcher_main.preflight(manager, None, allow_game_path_prompt=False)
        output = "\n".join(call.args[0] for call in line.call_args_list)
        self.assertIn("input_signature", output)
        self.assertIn("FAILED: YARA unavailable", output)

    def test_ready_module_uses_launcher_python_and_shared_clock(self):
        with mock.patch.object(modules, "yara_runtime_error", return_value=""):
            scanner = modules.input_signature_module()
        argv = scanner.resolved({"session": "normal_001", "player": "player_042",
                                 "t0": "1000.250", "telemetry": "off"})
        self.assertEqual(argv[0], sys.executable)
        self.assertEqual(argv[argv.index("--t0") + 1], "1000.250")
        self.assertEqual(argv[argv.index("--timeout") + 1], "120")
        self.assertGreater(scanner.stop_grace_s, modules.YARA_TIMEOUT_S)
        self.assertFalse(scanner.restart)
        self.assertNotIn("--auto-external-python", argv)


if __name__ == "__main__":
    unittest.main()
