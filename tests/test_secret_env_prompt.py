"""Deterministic local tests. All input values are deliberately dummy data."""

import contextlib
import importlib.util
import io
import json
import os
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "secret_env_prompt.py"
SPEC = importlib.util.spec_from_file_location("secret_env_prompt", SCRIPT)
prompt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prompt)


class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hsp-test-")
        self.root = Path(self.temporary.name)
        self.bash = shutil.which("bash")
        if self.bash is None:
            self.skipTest("Bash is required for actual local export verification")

    def tearDown(self):
        self.temporary.cleanup()

    def fifo(self, name="verify.pipe"):
        path = self.root / name
        os.mkfifo(path, 0o600)
        return str(path)

    def store(self, name, variable, value, fifo=None):
        path, directory, basename = prompt.open_destination(str(self.root / name))
        try:
            prompt.store_export(directory, basename, path, variable, value,
                                fifo or self.fifo(), time.monotonic() + 10, self.bash)
        finally:
            os.close(directory)
        return Path(path)

    def test_actual_bash_exact_roundtrip_permissions_and_no_extra_copies(self):
        marker = self.root / "must-not-exist"
        values = ["", "dummy-simple", "  dummy spaces  ", "dummy'quote\"$()`false`",
                  "dummy\\backslash\r\nline\n", "dummy-π-🔒", "dummy\tvalue",
                  "dummy'$(touch " + str(marker) + ")`touch " + str(marker) + "`"]
        for index, value in enumerate(values):
            with self.subTest(index=index):
                fifo = self.fifo("verify-" + str(index))
                path = self.store("out-" + str(index), "DUMMY_KEY", value, fifo)
                info = path.stat()
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                self.assertEqual(info.st_uid, os.getuid())
                self.assertEqual(info.st_nlink, 1)
                prompt.verify_export(str(path), "DUMMY_KEY", value, fifo,
                                     time.monotonic() + 10, self.bash)
        self.assertFalse(marker.exists())
        self.assertFalse(any(p.name.startswith(".secret-prompt-") for p in self.root.iterdir()))

    def test_maximum_value_streams_through_real_verification_fifo(self):
        value = "dummy\n" + "x" * (prompt.MAX_SECRET_BYTES - 6)
        self.store("maximum.env", "DUMMY_KEY", value)

    def test_verification_requires_equal_value_and_export_attribute(self):
        fifo = self.fifo()
        path = self.root / "candidate"
        path.write_text("export DUMMY_KEY='dummy-one'\n")
        with self.assertRaises(prompt.PromptError):
            prompt.verify_export(str(path), "DUMMY_KEY", "dummy-other", fifo,
                                 time.monotonic() + 10, self.bash)
        path.write_text("DUMMY_KEY='dummy-one'\n")
        with self.assertRaises(prompt.PromptError):
            prompt.verify_export(str(path), "DUMMY_KEY", "dummy-one", fifo,
                                 time.monotonic() + 10, self.bash)

    def test_verifier_internal_names_cannot_clobber_requested_variable(self):
        for index, variable in enumerate(("name", "expected", "__hsp_expected", "PATH", "IFS")):
            with self.subTest(variable=variable):
                self.store("name-" + str(index), variable, "dummy-value",
                           self.fifo("fifo-" + str(index)))

    def test_existing_empty_file_and_dangling_symlink_are_untouched(self):
        target = self.root / "existing"
        target.write_bytes(b"")
        target.chmod(0o644)
        before = target.stat()
        with self.assertRaises(prompt.PromptError):
            prompt.open_destination(str(target))
        self.assertEqual(target.read_bytes(), b"")
        self.assertEqual(target.stat().st_ino, before.st_ino)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
        dangling = self.root / "dangling"
        dangling.symlink_to(self.root / "absent")
        with self.assertRaises(prompt.PromptError):
            prompt.open_destination(str(dangling))
        self.assertTrue(dangling.is_symlink())
        self.assertFalse((self.root / "absent").exists())

    def test_parent_symlinks_and_writable_parents_are_refused(self):
        real = self.root / "real"
        real.mkdir(mode=0o700)
        link = self.root / "link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(prompt.PromptError):
            prompt.open_destination(str(link / "new.env"))
        real.chmod(0o777)
        with self.assertRaises(prompt.PromptError):
            prompt.open_destination(str(real / "new.env"))
        self.assertFalse((real / "new.env").exists())

    def test_git_directory_and_worktree_marker_refused_before_mkdir(self):
        for index, directory_marker in enumerate((False, True)):
            repository = self.root / ("repo-" + str(index))
            repository.mkdir(mode=0o700)
            marker = repository / ".git"
            if directory_marker:
                marker.mkdir()
            else:
                marker.write_text("gitdir: /dummy/not-used\n")
            with self.assertRaises(prompt.PromptError):
                prompt.open_destination(str(repository / "new" / "key.env"))
            self.assertFalse((repository / "new").exists())

    def test_new_parents_are_private(self):
        path, directory, _ = prompt.open_destination(str(self.root / "a" / "b" / "out.env"))
        os.close(directory)
        self.assertEqual(stat.S_IMODE((self.root / "a").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / "a" / "b").stat().st_mode), 0o700)
        self.assertFalse(Path(path).exists())

    def test_competing_target_created_after_preflight_is_preserved(self):
        target = self.root / "out.env"
        path, directory, basename = prompt.open_destination(str(target))
        target.write_bytes(b"dummy-existing\n")
        try:
            with self.assertRaises(prompt.PromptError):
                prompt.store_export(directory, basename, path, "DUMMY_KEY", "dummy-new",
                                    self.fifo(), time.monotonic() + 10, self.bash)
        finally:
            os.close(directory)
        self.assertEqual(target.read_bytes(), b"dummy-existing\n")
        self.assertFalse(any(p.name.startswith(".secret-prompt-") for p in self.root.iterdir()))

    def test_actual_concurrent_publish_has_exactly_one_winner(self):
        target = self.root / "race.env"
        destinations = [prompt.open_destination(str(target)) for _ in range(2)]
        fifos = [self.fifo("race-" + str(index)) for index in range(2)]
        barrier = threading.Barrier(2)
        outcomes = []

        def writer(index):
            path, directory, basename = destinations[index]
            try:
                barrier.wait(timeout=5)
                prompt.store_export(directory, basename, path, "DUMMY_KEY",
                                    "dummy-" + str(index), fifos[index],
                                    time.monotonic() + 10, self.bash)
                outcomes.append("saved")
            except prompt.PromptError:
                outcomes.append("refused")
            finally:
                os.close(directory)

        threads = [threading.Thread(target=writer, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertCountEqual(outcomes, ["saved", "refused"])
        self.assertIn(target.read_bytes(), [prompt.export_bytes("DUMMY_KEY", "dummy-0"),
                                           prompt.export_bytes("DUMMY_KEY", "dummy-1")])
        self.assertFalse(any(p.name.startswith(".secret-prompt-") for p in self.root.iterdir()))

    def test_replaced_parent_is_not_published_through_old_directory_fd(self):
        parent = self.root / "parent"
        parent.mkdir(mode=0o700)
        path, directory, basename = prompt.open_destination(str(parent / "out.env"))
        moved = self.root / "moved"
        parent.rename(moved)
        parent.mkdir(mode=0o700)
        try:
            with self.assertRaises(prompt.PromptError):
                prompt.store_export(directory, basename, path, "DUMMY_KEY", "dummy-value",
                                    self.fifo(), time.monotonic() + 10, self.bash)
        finally:
            os.close(directory)
        self.assertEqual(list(moved.iterdir()), [])
        self.assertEqual(list(parent.iterdir()), [])

    def test_invalid_value_leaves_no_temporary_or_destination(self):
        with self.assertRaises(prompt.PromptError):
            self.store("invalid.env", "DUMMY_KEY", "dummy\x00value")
        self.assertFalse((self.root / "invalid.env").exists())
        self.assertFalse(any(p.name.startswith(".secret-prompt-") for p in self.root.iterdir()))

    def test_expired_storage_deadline_removes_its_private_temporary(self):
        path, directory, basename = prompt.open_destination(str(self.root / "expired.env"))
        try:
            with self.assertRaises(prompt.PromptTimeout):
                prompt.store_export(directory, basename, path, "DUMMY_KEY", "dummy-value",
                                    self.fifo(), time.monotonic() - 1, self.bash)
        finally:
            os.close(directory)
        self.assertFalse(Path(path).exists())
        self.assertFalse(any(p.name.startswith(".secret-prompt-") for p in self.root.iterdir()))

    def test_quoted_and_unicode_destination_is_sourced_literally(self):
        parent = self.root / "dummy ' \" $() π\nfolder"
        parent.mkdir(mode=0o700)
        target = parent / "dummy ' \" env.file"
        self.store(str(target), "DUMMY_KEY", "dummy-value")


class InputAndPrivacyTests(unittest.TestCase):
    def test_only_one_framing_newline_is_removed(self):
        self.assertEqual(prompt.decode_input(b"  dummy\r\n\n"), "  dummy\r\n")
        self.assertEqual(prompt.decode_input(b"dummy\r"), "dummy\r")
        self.assertEqual(prompt.decode_input(b"dummy"), "dummy")

    def test_empty_dialog_response_does_not_become_a_credential(self):
        self.assertIsNone(prompt.decode_input(b""))
        self.assertIsNone(prompt.decode_input(b"\n"))

    def test_size_nul_and_encoding_boundaries(self):
        maximum = b"x" * prompt.MAX_SECRET_BYTES
        self.assertEqual(prompt.decode_input(maximum + b"\n"), maximum.decode())
        for value in (b"x" * (prompt.MAX_SECRET_BYTES + 1), b"dummy\x00", b"\xff"):
            with self.subTest(length=len(value)), self.assertRaises(prompt.PromptError):
                prompt.decode_input(value)

    def test_invalid_arguments_do_not_disclose_unknown_argument_values(self):
        marker = "DUMMY_PRIVATE_VALUE_NEVER_PRINT"
        result = subprocess.run([sys.executable, str(SCRIPT), "--unexpected", marker],
                                capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(marker.encode(), result.stdout + result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(json.loads(result.stdout)["status"], "error")

    def test_invalid_timeout_is_secret_safe(self):
        marker = "DUMMY_PRIVATE_TIMEOUT_NEVER_PRINT"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = prompt.main(["--var", "DUMMY_KEY", "--file", "/dummy/not-created",
                                "--timeout", marker])
        self.assertEqual(code, 1)
        self.assertNotIn(marker, output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "error")

    def test_existing_dummy_credential_never_appears_in_diagnostics(self):
        marker = b"DUMMY_EXISTING_PRIVATE_VALUE_NEVER_PRINT"
        with tempfile.TemporaryDirectory(prefix="hsp-private-test-") as root:
            target = Path(root) / "existing.env"
            target.write_bytes(marker)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--var", "DUMMY_KEY", "--file", str(target)],
                capture_output=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(marker, result.stdout + result.stderr)
            self.assertEqual(result.stderr, b"")
            self.assertEqual(json.loads(result.stdout)["status"], "error")
            self.assertEqual(target.read_bytes(), marker)


class RuntimeBoundaryTests(unittest.TestCase):
    def test_ipc_root_must_be_a_private_real_directory(self):
        with tempfile.TemporaryDirectory(prefix="hsp-runtime-test-") as root:
            runtime = Path(root) / "runtime"
            runtime.mkdir(mode=0o755)
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(runtime)}), \
                    self.assertRaises(prompt.PromptError):
                prompt._runtime_directory()
            runtime.chmod(0o700)
            link = Path(root) / "linked"
            link.symlink_to(runtime, target_is_directory=True)
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(link)}), \
                    self.assertRaises(prompt.PromptError):
                prompt._runtime_directory()
            not_directory = Path(root) / "file"
            not_directory.write_text("dummy")
            not_directory.chmod(0o600)
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(not_directory)}), \
                    self.assertRaises(prompt.PromptError):
                prompt._runtime_directory()


@unittest.skipUnless(hasattr(signal, "pthread_sigmask"), "POSIX signal masking required")
class CommitStateTests(unittest.TestCase):
    def test_interrupt_after_verified_publish_reports_saved_not_cancelled(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("Bash is required for actual export verification")
        actual_store = prompt.store_export

        def entered_dummy(variable, instance, deadline, hyprctl, zenity, private):
            fifo = os.path.join(private, "verify.pipe")
            os.mkfifo(fifo, 0o600)
            return "dummy-commit-value", fifo

        def published_then_interrupted(*args):
            actual_store(*args)
            os.kill(os.getpid(), signal.SIGINT)

        def available_program(name):
            return bash if name == "bash" else sys.executable

        with tempfile.TemporaryDirectory(prefix="hsp-commit-test-") as root:
            target = Path(root) / "saved.env"
            output = io.StringIO()
            with mock.patch.object(prompt, "choose_instance", return_value="test-instance"), \
                    mock.patch.object(prompt, "prompt_value", side_effect=entered_dummy), \
                    mock.patch.object(prompt, "store_export", side_effect=published_then_interrupted), \
                    mock.patch.object(prompt.shutil, "which", side_effect=available_program), \
                    mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": root}), \
                    contextlib.redirect_stdout(output):
                code = prompt.main(["--var", "DUMMY_KEY", "--file", str(target)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "saved")
            self.assertTrue(target.is_file())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertNotIn("dummy-commit-value", output.getvalue())


@unittest.skipUnless(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
                     "Linux pidfds required")
class OwnedLauncherTests(unittest.TestCase):
    def test_handshake_wait_is_bounded(self):
        with tempfile.TemporaryDirectory(prefix="hsp-launch-test-") as root, \
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(os.path.join(root, "control.sock"))
            listener.listen(1)
            with self.assertRaises(prompt.PromptTimeout):
                prompt._owned_connection(listener, time.monotonic() + 0.02)

    def test_exec_failure_is_control_only_and_never_success(self):
        with tempfile.TemporaryDirectory(prefix="hsp-launch-test-") as root:
            control = os.path.join(root, "control.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(control)
                listener.listen(1)
                process = subprocess.Popen(
                    [sys.executable, "-c", prompt.LAUNCHER, control,
                     os.path.join(root, "nonexistent"), "dummy title", "5", os.devnull],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                connection = None
                pidfd = None
                try:
                    connection, pidfd = prompt._owned_connection(listener, time.monotonic() + 5)
                    connection.sendall(b"G")
                    self.assertEqual(connection.recv(1), b"E")
                    stdout, stderr = process.communicate(timeout=5)
                    self.assertEqual((stdout, stderr), (b"", b""))
                    self.assertNotEqual(process.returncode, 0)
                finally:
                    if connection is not None:
                        connection.close()
                    if pidfd is not None:
                        prompt._close_owned_prompt(pidfd)
                    if process.poll() is None:
                        process.kill()
                    process.wait()

    def test_authenticated_exec_same_pid_and_owned_cleanup_leaves_other_child_alive(self):
        # A real, harmless executable stands in for Zenity: this tests the actual
        # kernel socket credentials/exec/pidfd boundary without opening any GUI.
        with tempfile.TemporaryDirectory(prefix="hsp-launch-test-") as root:
            control = os.path.join(root, "control.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(control)
            listener.listen(1)
            sleeper = Path(root) / "sleep-tool"
            sleeper.write_text("#!/bin/sh\nexec sleep 30\n")
            sleeper.chmod(0o700)
            unrelated = subprocess.Popen(["sleep", "30"])
            launched = subprocess.Popen([sys.executable, "-c", prompt.LAUNCHER, control,
                                         str(sleeper), "dummy title", "10", os.devnull],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pidfd = None
            connection = None
            try:
                connection, pidfd = prompt._owned_connection(listener, time.monotonic() + 10)
                peer_pid, peer_uid, _ = struct.unpack(
                    "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                self.assertEqual(peer_pid, launched.pid)
                self.assertEqual(peer_uid, os.getuid())
                connection.sendall(b"G")
                self.assertEqual(connection.recv(1), b"")
                self.assertIsNone(launched.poll())
                prompt._close_owned_prompt(pidfd)
                pidfd = None
                self.assertEqual(launched.wait(timeout=5), -signal.SIGKILL)
                self.assertIsNone(unrelated.poll())
            finally:
                if connection is not None:
                    connection.close()
                listener.close()
                if pidfd is not None:
                    prompt._close_owned_prompt(pidfd)
                for process in (launched, unrelated):
                    if process.poll() is None:
                        process.kill()
                    process.wait()

    def test_unacknowledged_launcher_cannot_exec_after_owner_disconnects(self):
        with tempfile.TemporaryDirectory(prefix="hsp-launch-test-") as root:
            control = os.path.join(root, "control.sock")
            marker = Path(root) / "must-not-exist"
            tool = Path(root) / "mark-tool"
            tool.write_text("#!/bin/sh\n: > " + prompt.shell_quote(str(marker)) + "\n")
            tool.chmod(0o700)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(control)
            listener.listen(1)
            process = subprocess.Popen([sys.executable, "-c", prompt.LAUNCHER, control,
                                        str(tool), "dummy title", "5", os.devnull],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pidfd = None
            try:
                connection, pidfd = prompt._owned_connection(listener, time.monotonic() + 5)
                connection.close()
                listener.close()
                self.assertNotEqual(process.wait(timeout=5), 0)
                self.assertFalse(marker.exists())
            finally:
                listener.close()
                if pidfd is not None:
                    prompt._close_owned_prompt(pidfd)
                if process.poll() is None:
                    process.kill()
                process.wait()


if __name__ == "__main__":
    unittest.main()
