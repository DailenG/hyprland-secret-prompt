---
name: hyprland-secret-prompt
description: Collect an API key, token, password, or other credential through a native masked Hyprland dialog and save a private Bash export file. Use when a user needs to enter a secret locally without putting it in chat, command arguments, or tool output.
license: MIT
compatibility: Linux with modern Lua-configured Hyprland, hyprctl, Zenity, Bash, and Python 3.9+ with os.pidfd_open and signal.pidfd_send_signal. Requires /proc, a private XDG_RUNTIME_DIR or /run/user/UID, and an active local graphical session. No legacy Hyprland, macOS, or Windows support. No network access is needed.
---

# Masked credential prompt

Use [scripts/secret_env_prompt.py](scripts/secret_env_prompt.py) from this skill's root. See [README.md](README.md) for installation, CLI details, loading, and limitations.

## Workflow

1. Establish the destination variable and a new private file outside every Git working tree. Use a POSIX shell variable name, such as `EXAMPLE_API_KEY`. Never ask the user to paste the secret into chat or provide it yourself.
2. Tell the user before opening the real dialog: what credential they will enter, which variable/file it will save, and that the file is plaintext with mode `0600`, not encrypted. Saving a credential does not authorize API requests or billing.
3. From the skill root, launch the prompt with metadata only:

   ```bash
   python3 scripts/secret_env_prompt.py \
     --var EXAMPLE_API_KEY \
     --file "$HOME/.config/example-service/key.env" \
     --timeout 120
   ```

   The human types directly into the masked Zenity dialog. Do not automate entry, paste from the clipboard, inspect the dialog's contents, or read an existing real credential. For an ambiguous multi-compositor session, select the intended signature from `hyprctl instances -j` and pass `--instance SIGNATURE`; do not guess.
4. Interpret JSON metadata and exit status: `saved`/0, `cancelled`/2, `timeout`/124, or `error`/1. Argument/validation errors return 1. `cancelled` means no credential or a blank response; post-launch display failure and human cancellation can be indistinguishable. Local export verification is not provider authentication. No credential is saved on cancellation, timeout, or failure; once committed, a late interrupt reports `saved`. Do not retry or reopen a dialog without the user's knowledge.
5. Explain how the intended consumer loads the export. In a trusted Bash shell with no tracing/debug hooks that expose values:

   ```bash
   set +x
   source "$HOME/.config/example-service/key.env"
   ```

   Source only the private file this tool created for the user: sourcing executes shell code. The export applies to that shell and its later child processes, not all terminals, existing applications, or the agent's parent process. Never edit shell startup files automatically.

## Boundaries

- No secret CLI argument or stdin-input mode exists. Do not invent one. Never `cat`, `echo`, `env`, `printenv`, hash, log, or otherwise dump the credential or its file.
- Existing destinations, including empty files and dangling symlinks, are refused. There is no overwrite flag. Do not delete, truncate, rename, or chmod an existing credential to bypass that refusal.
- Keep credentials outside Git, websites, and client-side JavaScript. `.gitignore` is not a security boundary. Do not place secret bytes in command arguments, chat, screenshots, test fixtures, or tool output.
- The private FIFO and mode-`0600` export file reduce accidental exposure, not compromise by the same OS user, root, a hostile compositor, debugging/tracing, or backups. There is no encryption or keyring integration.
- Do not install dependencies, change Hyprland configuration, reload the compositor, modify the clipboard, or make network/provider calls as part of collection. Never kill unrelated windows or processes.
- Tests must use dummy values only. Do not re-read or re-enter a real credential for verification. Do not claim API validity or permission to spend money.
