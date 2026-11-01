# hyprland-secret-prompt

A local masked credential prompt for modern Lua-configured Hyprland. A human enters a secret in Zenity; the tool saves one safely quoted Bash `export` statement in a new private file outside Git. It makes no provider or other network calls.

## Requirements

- Linux and an active **modern Lua-configured Hyprland** session, with `hyprctl` available.
- Zenity, Python 3.9 or newer (standard library only), and Bash available locally. Python/Linux must provide `os.pidfd_open` and `signal.pidfd_send_signal`; Linux `/proc` must be mounted. IPC uses a real, current-user-owned mode-`0700` `XDG_RUNTIME_DIR`, or `/run/user/UID` when unset.
- A destination outside every Git working tree, with a safely owned parent path. Missing parent directories are created with mode `0700`; unsafe ownership or permissions and symlinked path components are refused. The final file must not already exist.

This is not a legacy Hyprland configuration tool and does not support macOS or Windows. Install prerequisites separately; the script does not install packages, modify shell startup files, add permanent window rules, or reload Hyprland.

```bash
git clone https://github.com/DailenG/hyprland-secret-prompt.git
cd hyprland-secret-prompt
```

## Run

Run from this repository's root. The names and destination below are generic examples; type the actual credential only into the dialog.

```bash
python3 scripts/secret_env_prompt.py \
  --var EXAMPLE_API_KEY \
  --file "$HOME/.config/example-service/key.env" \
  --timeout 120
```

Notify the person before opening a real dialog, identifying its purpose and destination. The tool asks the selected compositor to launch Zenity directly with temporary floating/centering rules, so the prompt uses the compositor's actual graphical session rather than relying on the caller's `DISPLAY` or `WAYLAND_DISPLAY`. The masked entry is not a clipboard or chat workflow.

### CLI

```text
python3 scripts/secret_env_prompt.py --var NAME --file PATH [--timeout SECONDS] [--instance SIGNATURE]
```

| Option | Meaning |
| --- | --- |
| `--var NAME` | Required. POSIX shell variable syntax: `[A-Za-z_][A-Za-z0-9_]*`. Use an application-specific name; Bash reserved/readonly names can fail local verification and are not saved. |
| `--file PATH` | Required. New export file outside Git. Quote shell paths; `"$HOME/..."` expands safely in Bash. |
| `--timeout SECONDS` | Finite wait from 1 to 3600 seconds; default 120 seconds. |
| `--instance SIGNATURE` | Explicit Hyprland instance signature for a multi-compositor session. |

Without `--instance`, selection uses a valid connected session signature or exactly one discovered instance. If the session is ambiguous, inspect `hyprctl instances -j`, identify the intended compositor, and pass its signature. The tool does not guess among ambiguous sessions.

There is no secret/value argument, stdin-input option, overwrite flag, or replacement mode. Existing files are refused before a dialog opens, including empty files and dangling symlinks. Detected Git working trees and unsafe symlink/ownership paths are rejected. Do not delete or change an existing destination merely to bypass refusal; choose an intentionally new destination with the user's agreement.

Stdout contains JSON metadata only: `status` (`saved`, `cancelled`, `timeout`, or `error`), with `variable`, `file`, `mode`, and `export_verified` as applicable. Diagnostics must not contain secret values.

| Result | Exit code | Meaning |
| --- | --- | --- |
| `saved` | 0 | A new private export was published and verified locally. |
| `cancelled` | 2 | The prompt ended without credential output; no credential was saved. |
| `timeout` | 124 | The bounded wait expired; no credential was saved. |
| `error` | 1 | Launch, validation, or storage failed; no credential was saved. |

`cancelled` means the prompt ended with no credential or a blank response. A Zenity runtime/display failure after successful launch can produce the same result as human cancellation; neither saves a credential. Detected launch/exec and argument/validation failures return `error`/1.

Cancellation, timeout, and launch failure clean up the owned prompt and temporary resources, without killing other dialogs or processes. An existing target remains unchanged, including if another process creates it during the prompt. Final verified publication defers interruption until its result is known: once committed, a late interrupt reports `saved`, not a misleading cancellation.

## Load for a consumer

The saved file is **plaintext, not encrypted**, owned by the current user with mode `0600`. It is not automatically loaded into your terminal, another application, or all shells.

In the trusted Bash shell that will launch the consumer, disable tracing before loading:

```bash
set +x
source "$HOME/.config/example-service/key.env"
```

Use a shell without debug traps, logging hooks, or prompt instrumentation that exposes values. Source only the user-owned file produced for this purpose: `source` executes shell code and is not safe for arbitrary downloaded files. The exported variable is available to that shell and its subsequently launched child processes. Already running consumers and other terminals need their own deliberate loading step. No global environment or shell startup change is performed. Do not turn tracing back on around commands that expand the secret.

Never verify by printing the variable or file. The tool's `export_verified` metadata describes a local export check, **not** authentication, credential validity, service authorization, or permission for API usage/billing. Running a consumer that contacts a provider requires separate authorization.

## Install as a local Agent Skill

The CLI works without skill installation. To make [SKILL.md](SKILL.md) discoverable, run the following from this repository's root:

```bash
mkdir -p "$HOME/.agents/skills"
ln -s -- "$PWD" "$HOME/.agents/skills/hyprland-secret-prompt"
```

Keep the checkout at that location after linking. If an entry already exists at the skill path, inspect it and resolve the conflict deliberately; do not use a forced replacement. The skill directory name must remain `hyprland-secret-prompt`. Agent hosts that support `~/.agents/skills` can discover the symlink according to their own reload/startup behavior.

## Security boundaries

- Entered secret bytes travel through a private local FIFO, not launching command arguments, the launcher's environment, the CLI's stdout/stderr, or chat. Zenity's stdout is redirected directly to that FIFO. The temporary directory is mode `0700`; the FIFO and final export file are mode `0600`.
- Input is limited to 65,536 UTF-8 bytes, excluding exactly one Zenity framing newline; NUL, invalid UTF-8, and oversized input are rejected. Meaningful input is preserved. The export is shell-quoted, written durably, and published atomically without clobbering an existing target. Temporary resources are removed on exit.
- Permissions and safe path handling mitigate accidental disclosure to other unprivileged users. They do **not** protect against root, another process running as the same user, a compromised shell/compositor/Zenity, tracing/debuggers, malware, screen recording, or backups. A masked field hides on-screen entry; it is not cryptographic protection. A loaded credential is part of the consumer's process environment.
- Never paste credentials into chat, command arguments, source code, tests, websites, or client-side JavaScript. Never `cat`, `echo`, `env`, `printenv`, hash, log, or otherwise dump the credential file/value. Do not capture real credentials in screenshots or test artifacts.
- Keep real outputs outside version control. The tool detects Git working trees by ancestor `.git` files/directories; unusual bare repositories or externally configured worktrees cannot be identified universally. The caller must still choose an appropriate private destination. [.gitignore](.gitignore) is only a backstop: ignored files can still be force-added, copied, backed up, or disclosed.
- There is no encryption, keyring storage, clipboard manipulation, provider validation, or automatic permission to use a credential. Do not re-read or automatically re-enter real credentials for tests; use dummy values only.

## Verification

```bash
python3 -m unittest discover -s tests -v
ruff check scripts tests
uvx --from skills-ref==0.1.0 agentskills validate "$PWD"
```

Ruff and the reference skill validator are optional development tools, not runtime dependencies. Pass an absolute path to the published validator; its `.` path handling does not resolve the skill directory name correctly.

Verified on Linux with Hyprland **0.56.2** and Python **3.14**:

- **26 regression tests** cover exact Bash export roundtrips, quoting/injection boundaries, Unicode/newlines, input limits, file permissions, symlink/Git refusal, concurrent no-clobber publication, diagnostic privacy and owned-process cleanup.
- Real Hyprland dialogs were floating and centered in the monitor workarea. A human-entered dummy save produced an owner-only `0600` file and passed exact local export verification without printing its value.
- Reusing the destination was refused without modifying it. Closing an empty test dialog and allowing another to time out both removed their owned prompts and saved nothing.
- Regressions reproduced and fixed blank-input false success and interruption just after successful publication. These checks are not a security certification, provider authentication or a guarantee against a compromised same-user session.

## License

[MIT](LICENSE), copyright 2026 DailenG.
