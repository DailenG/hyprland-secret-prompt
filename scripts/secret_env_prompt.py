#!/usr/bin/env python3
"""Masked, compositor-native credential entry; never print credential material."""

import argparse
import errno
import json
import math
import os
import re
import selectors
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

MAX_SECRET_BYTES = 65536
MAX_TIMEOUT = 3600
VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z", re.ASCII)
INTERRUPT_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class PromptError(Exception):
    """Only fixed, credential-independent messages may be supplied."""


class PromptTimeout(PromptError):
    pass


# This process never forks: its PID becomes Zenity's PID. The socket contains
# control bytes only. CLOEXEC lets the owner distinguish exec failure from exec.
LAUNCHER = r'''
import os, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(float(sys.argv[4]))
try:
    s.connect(sys.argv[1])
    s.sendall(b"READY")
    if s.recv(1) != b"P":
        sys.exit(1)
    s.sendall(b"LIVE")
    if s.recv(1) != b"G":
        sys.exit(1)
    try:
        output = os.open(sys.argv[5], os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        os.set_blocking(output, True)
        os.dup2(output, 1)
        if output != 1:
            os.close(output)
        os.execv(sys.argv[2], [sys.argv[2], "--password", "--title=" + sys.argv[3]])
    except BaseException:
        s.sendall(b"E")
        sys.exit(1)
except BaseException:
    sys.exit(1)
finally:
    s.close()
'''

# The expected value travels over the same private FIFO, never argv/environment.
# Bash reads the canonical file and checks exact value and export attribute.
VERIFY = r'''
set +x
unset BASH_ENV ENV
. "$1" || exit 1
IFS= read -r -d '' "$4" < "$3" || exit 1
[[ ${!2} == "${!4}" && ${!2@a} == *x* ]]
'''


def remaining(deadline):
    duration = deadline - time.monotonic()
    if duration <= 0:
        raise PromptTimeout("Prompt timed out")
    return duration


def shell_quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def export_bytes(variable, value):
    if not VARIABLE.fullmatch(variable):
        raise PromptError("Invalid variable name")
    if "\x00" in value:
        raise PromptError("NUL input is not supported")
    return ("export " + variable + "=" + shell_quote(value) + "\n").encode("utf-8")


def decode_input(data):
    # Zenity appends one LF. Do not strip spaces, CRs, or user-entered newlines.
    if data.endswith(b"\n"):
        data = data[:-1]
    if not data:
        return None
    if len(data) > MAX_SECRET_BYTES:
        raise PromptError("Input exceeds the size limit")
    if b"\x00" in data:
        raise PromptError("NUL input is not supported")
    try:
        return data.decode("utf-8")
    except UnicodeError:
        raise PromptError("Input is not valid UTF-8") from None


def _exists(directory, name):
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def open_destination(filename, create=True):
    """Pin a symlink-free, safe parent and refuse Git/existing destinations."""
    try:
        path = os.path.abspath(os.path.expanduser(filename))
        if "\x00" in path or path == os.path.sep:
            raise PromptError("Invalid destination")
        parts = path.split(os.path.sep)
        directory = os.open(os.path.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for component in parts[1:-1]:
                if _exists(directory, ".git"):
                    raise PromptError("Destination is inside a Git working tree")
                try:
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                except FileNotFoundError:
                    if not create:
                        raise PromptError("Destination parent changed") from None
                    try:
                        os.mkdir(component, 0o700, dir_fd=directory)
                    except FileExistsError:
                        pass
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                os.close(directory)
                directory = child
                info = os.fstat(directory)
                if info.st_uid not in (0, os.getuid()):
                    raise PromptError("Unsafe destination ownership")
                if info.st_mode & 0o022 and not (
                        info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                    raise PromptError("Unsafe writable destination parent")
            if _exists(directory, ".git"):
                raise PromptError("Destination is inside a Git working tree")
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise PromptError("Destination parent must be owned and protected")
            if _exists(directory, parts[-1]):
                raise PromptError("Destination already exists")
            result = directory
            directory = None
            return path, result, parts[-1]
        finally:
            if directory is not None:
                os.close(directory)
    except PromptError:
        raise
    except (OSError, ValueError):
        raise PromptError("Cannot safely access destination") from None


def _safe_environment(variable=None):
    environment = os.environ.copy()
    for name in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PS4"):
        environment.pop(name, None)
    if variable is not None:
        environment.pop(variable, None)
    return environment


def _wait_process(process, deadline):
    try:
        return process.wait(timeout=remaining(deadline))
    except subprocess.TimeoutExpired:
        raise PromptTimeout("Prompt timed out") from None


def verify_export(path, variable, value, fifo, deadline, bash):
    """Source and compare locally without a value-bearing stdout or argument."""
    # Remove ambient function exports, which Bash can otherwise import at startup.
    environment = {key: val for key, val in _safe_environment(variable).items()
                   if not key.startswith("BASH_FUNC_")}
    expected_name = "__hsp_expected"
    while expected_name == variable:
        expected_name += "_"
    process = subprocess.Popen(
        [bash, "--noprofile", "--norc", "-c", VERIFY, "verify-export",
         path, variable, fifo, expected_name], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=environment)
    writer = None
    try:
        while writer is None:
            remaining(deadline)
            if process.poll() is not None:
                raise PromptError("Local export verification failed")
            try:
                writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            except OSError as error:
                if error.errno != errno.ENXIO:
                    raise PromptError("Local export verification failed") from None
                time.sleep(min(0.01, remaining(deadline)))
        payload = value.encode("utf-8") + b"\x00"
        offset = 0
        while offset < len(payload):
            remaining(deadline)
            try:
                offset += os.write(writer, payload[offset:])
            except BlockingIOError:
                if process.poll() is not None:
                    raise PromptError("Local export verification failed")
                time.sleep(min(0.01, remaining(deadline)))
        os.close(writer)
        writer = None
        if _wait_process(process, deadline) != 0:
            raise PromptError("Local export verification failed")
    finally:
        if writer is not None:
            os.close(writer)
        if process.poll() is None:
            process.kill()  # Popen owns this child; no externally supplied PID.
        process.wait()


def store_export(directory, basename, path, variable, value, fifo, deadline, bash):
    """Durable temporary inode, verified before atomic no-clobber publication."""
    temporary = ".secret-prompt-" + os.urandom(16).hex()
    descriptor = None
    linked = False
    identity = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        os.fchmod(descriptor, 0o600)  # Only our newly created inode is changed.
        identity = os.fstat(descriptor)
        payload = export_bytes(variable, value)
        offset = 0
        while offset < len(payload):
            remaining(deadline)
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        # A pinned /proc path ensures sourcing the inode in the pinned parent.
        verify_export("/proc/" + str(os.getpid()) + "/fd/" + str(directory) +
                      "/" + temporary, variable, value, fifo, deadline, bash)
        remaining(deadline)
        _, current, _ = open_destination(path, create=False)
        try:
            before = os.fstat(directory)
            after = os.fstat(current)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise PromptError("Destination parent changed")
        finally:
            os.close(current)
        try:
            os.link(temporary, basename, src_dir_fd=directory,
                    dst_dir_fd=directory, follow_symlinks=False)
        except FileExistsError:
            raise PromptError("Destination already exists") from None
        linked = True
        os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
    except BaseException:
        if linked:
            try:
                current = os.stat(basename, dir_fd=directory, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                    os.unlink(basename, dir_fd=directory)
                    os.fsync(directory)
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def _run_hyprctl(arguments, deadline):
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=min(5, remaining(deadline)), check=False)
    except subprocess.TimeoutExpired:
        remaining(deadline)
        raise PromptError("Hyprland did not respond") from None
    except OSError:
        raise PromptError("Cannot contact Hyprland") from None
    if result.returncode != 0:
        raise PromptError("Hyprland command failed")
    return result.stdout


def choose_instance(hyprctl, explicit, deadline):
    try:
        instances = json.loads(_run_hyprctl([hyprctl, "instances", "-j"], deadline))
        if not isinstance(instances, list):
            raise TypeError
        signatures = {entry["instance"] for entry in instances
                      if isinstance(entry, dict) and isinstance(entry.get("instance"), str)
                      and entry.get("instance") and isinstance(entry.get("wl_socket"), str)
                      and entry.get("wl_socket")}
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise PromptError("Cannot discover Hyprland instances") from None
    if explicit is not None:
        if explicit not in signatures:
            raise PromptError("Requested Hyprland instance is not available")
        return explicit
    connected = os.environ.get("HYPRLAND_INSTANCE_SIGNATURE")
    if connected in signatures:
        return connected
    if len(signatures) != 1:
        raise PromptError("Select one available Hyprland instance explicitly")
    return next(iter(signatures))


def _lua_string(value):
    # Fixed-width decimal escapes preserve arbitrary UTF-8 paths and controls;
    # unlike JSON's \\uNNNN escapes, this syntax is valid in Lua strings.
    pieces = []
    for byte in value.encode("utf-8"):
        if 32 <= byte < 127 and byte not in (34, 92):
            pieces.append(chr(byte))
        else:
            pieces.append("\\" + format(byte, "03d"))
    return '"' + "".join(pieces) + '"'


def _owned_connection(listener, deadline):
    listener.settimeout(remaining(deadline))
    try:
        connection, _ = listener.accept()
    except socket.timeout:
        raise PromptTimeout("Prompt timed out") from None
    try:
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        pid, uid, _ = struct.unpack("3i", credentials)
        if uid != os.getuid() or pid <= 1:
            raise PromptError("Invalid prompt ownership handshake")
        # A post-pidfd challenge proves this peer was still alive after opening
        # the pidfd. Even an externally killed launcher/PID reuse cannot make
        # us return a pidfd belonging to an unrelated process.
        pidfd = os.pidfd_open(pid, 0)
        try:
            connection.settimeout(remaining(deadline))
            ready = bytearray()
            while len(ready) < 5:
                part = connection.recv(5 - len(ready))
                if not part:
                    raise PromptError("Prompt launch failed")
                ready.extend(part)
            if ready != b"READY":
                raise PromptError("Invalid prompt ownership handshake")
            connection.sendall(b"P")
            live = bytearray()
            while len(live) < 4:
                part = connection.recv(4 - len(live))
                if not part:
                    raise PromptError("Prompt launch failed")
                live.extend(part)
            if live != b"LIVE":
                raise PromptError("Invalid prompt ownership handshake")
            return connection, pidfd
        except BaseException:
            os.close(pidfd)
            raise
    except BaseException:
        connection.close()
        raise


def _close_owned_prompt(pidfd):
    if pidfd is None:
        return
    try:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        os.close(pidfd)


def prompt_value(variable, instance, deadline, hyprctl, zenity, private):
    fifo = os.path.join(private, "secret.pipe")
    control = os.path.join(private, "launch.sock")
    os.mkfifo(fifo, 0o600)
    os.chmod(fifo, 0o600)
    reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    holder = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection = None
    pidfd = None
    try:
        listener.bind(control)
        os.chmod(control, 0o600)
        listener.listen(1)
        title = "Credential for " + variable
        argv = [sys.executable, "-c", LAUNCHER, control, zenity, title,
                str(remaining(deadline)), fifo]
        command = "exec " + " ".join(shell_quote(argument) for argument in argv)
        command += " >/dev/null 2>/dev/null"
        dispatch = ("hl.dsp.exec_cmd(" + _lua_string(command) +
                    ", { float = true, center = true, size = {520, 220} })")
        _run_hyprctl([hyprctl, "-i", instance, "dispatch", dispatch], deadline)
        connection, pidfd = _owned_connection(listener, deadline)
        connection.sendall(b"G")
        connection.settimeout(remaining(deadline))
        try:
            if connection.recv(1) != b"":
                raise PromptError("Prompt executable could not start")
        except socket.timeout:
            raise PromptTimeout("Prompt timed out") from None
        connection.close()
        connection = None
        data = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(reader, selectors.EVENT_READ)
            selector.register(pidfd, selectors.EVENT_READ)
            exited = False
            while True:
                events = selector.select(remaining(deadline))
                if not events:
                    raise PromptTimeout("Prompt timed out")
                for key, _ in events:
                    if key.fd == pidfd:
                        exited = True
                # Drain all available bytes, including bytes queued at exit.
                while True:
                    try:
                        part = os.read(reader, min(8192, MAX_SECRET_BYTES + 2 - len(data)))
                    except BlockingIOError:
                        break
                    if not part:
                        break
                    data.extend(part)
                    if len(data) > MAX_SECRET_BYTES + 1:
                        raise PromptError("Input exceeds the size limit")
                if exited:
                    break
        if not data:
            return None, fifo
        value = decode_input(bytes(data))
        return value, fifo
    finally:
        # Once the listener/connection closes, an unacknowledged late launcher
        # cannot become Zenity. Only the authenticated, pidfd-pinned peer is killed.
        if connection is not None:
            connection.close()
        listener.close()
        _close_owned_prompt(pidfd)
        os.close(holder)
        os.close(reader)


def _runtime_directory():
    # The compositor and caller must see the same private IPC directory.
    runtime = os.environ.get("XDG_RUNTIME_DIR") or "/run/user/" + str(os.getuid())
    try:
        info = os.stat(runtime, follow_symlinks=False)
    except (OSError, ValueError):
        raise PromptError("Private user runtime directory is unavailable") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PromptError("Private user runtime directory is unsafe")
    return runtime


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise PromptError("Invalid command-line arguments")


def parser():
    result = SafeParser(description=__doc__, allow_abbrev=False)
    result.add_argument("--var", required=True, help="POSIX environment variable name")
    result.add_argument("--file", required=True, help="new exported env file, outside Git")
    result.add_argument("--timeout", default="120", help="deadline in seconds, 1..3600")
    result.add_argument("--instance", help="explicit discovered Hyprland instance signature")
    return result


def _interrupted(signum, frame):
    raise KeyboardInterrupt


def main(argv=None):
    metadata = {"status": "error"}
    directory = None
    old_handlers = {}
    try:
        arguments = parser().parse_args(argv)
        if not VARIABLE.fullmatch(arguments.var):
            raise PromptError("Invalid variable name")
        try:
            timeout = float(arguments.timeout)
        except ValueError:
            raise PromptError("Invalid timeout") from None
        if not math.isfinite(timeout) or not 1 <= timeout <= MAX_TIMEOUT:
            raise PromptError("Timeout must be between 1 and 3600 seconds")
        metadata["variable"] = arguments.var
        path, directory, basename = open_destination(arguments.file)
        metadata["file"] = path
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise PromptError("Linux pidfd support is required")
        programs = [shutil.which(name) for name in ("hyprctl", "zenity", "bash")]
        if not all(programs):
            raise PromptError("Required local executable is unavailable")
        hyprctl, zenity, bash = programs
        deadline = time.monotonic() + timeout
        instance = choose_instance(hyprctl, arguments.instance, deadline)
        for signum in INTERRUPT_SIGNALS:
            old_handlers[signum] = signal.signal(signum, _interrupted)
        with tempfile.TemporaryDirectory(prefix="hyprland-secret-prompt-",
                                         dir=_runtime_directory()) as private:
            os.chmod(private, 0o700)
            value, fifo = prompt_value(arguments.var, instance, deadline,
                                       hyprctl, zenity, private)
            if value is None:
                metadata["status"] = "cancelled"
                return_code = 2
            else:
                # Defer cancellation through final publication and its result.
                # A late signal must not say "cancelled" after a committed save.
                blocked = signal.pthread_sigmask(signal.SIG_BLOCK, INTERRUPT_SIGNALS)
                try:
                    store_export(directory, basename, path, arguments.var, value,
                                 fifo, deadline, bash)
                    metadata.update(status="saved", mode="0600", export_verified=True)
                    return_code = 0
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
    except (PromptTimeout, socket.timeout):
        metadata.update(status="timeout", message="Prompt timed out")
        return_code = 124
    except KeyboardInterrupt:
        if metadata["status"] == "saved":
            return_code = 0
        else:
            metadata["status"] = "cancelled"
            return_code = 2
    except PromptError as error:
        metadata.update(status="error", message=str(error))
        return_code = 1
    except Exception:  # noqa: BLE001 - CLI privacy boundary: never dump unexpected exception data.
        # Never serialize exceptions: they can contain input, command arguments,
        # filesystem contents, or other private data.
        metadata.update(status="error", message="Local credential prompt failed")
        return_code = 1
    finally:
        if directory is not None:
            os.close(directory)
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
    print(json.dumps(metadata, ensure_ascii=True, separators=(",", ":")))
    return return_code


if __name__ == "__main__":
    sys.exit(main())
