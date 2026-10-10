# M1 manual check: terminal handoff

The TUI hands the terminal to the system `ssh` (`s`, `d`, `sm ssh`) and takes it back when the program exits. The PTY tests (`make test-pty`) cover this with a fake `ssh`; they cannot cover real terminal emulators. Run this checklist by hand before the M1 pull request is applied, once on macOS and once on Linux, and fill in the results table at the end.

## Setup

- Build and note the commit: `make build && ./dist/sm version`.
- Have one reachable SSH node added with `sm nodes add` (its `admin_user` must be able to log in with your agent or default key). Setup is not needed for checks 1 to 4 and 6.
- Check 5 needs a node with Docker readable by `admin_user` and `lazydocker` installed on it. SuperMgmt never installs it for you.
- macOS: run in Terminal.app and iTerm2. Linux: one terminal emulator of your choice (say which, and whether inside tmux).
- Start from a window of normal size. Open the TUI with `sm`, go to Resources (`2`), and put the cursor on the node.

## The six checks

**1. Shell and return.** Press `s`. A remote shell prompt appears. Type `exit`.
Expected: the TUI is back, on the same screen and selection, drawn completely (no leftover shell text, no missing borders), with the notice `back from shell on <node>`.

**2. Resize during the shell.** Press `s`. While in the shell, resize the window clearly smaller, then larger. Type `exit`.
Expected: the first frame after returning fits the new size; no stale rows or columns; the layout is correct at the new size. If the window is below the minimum size, the TUI shows `terminal too small` and recovers when you enlarge it.

**3. Nonzero exit code.** Press `s`, then type `exit 3`.
Expected: the TUI returns and shows the error notice `shell on <node> exited with code 3`. It does not crash or hang. Afterwards `sm events` should show the session end.

**4. Mouse and keys after return.** Press `s`, then `exit`. Now scroll with the mouse wheel or trackpad over the TUI, and press `j`, `k`, arrow keys, `2`, `3`, `?`, `esc`.
Expected: keys act as in a fresh TUI. The wheel produces no garbage characters on screen and does not move the terminal into a broken state (for example, printing `^[[A` or `65;..M` sequences). Quit with `q` and confirm your shell prompt, cursor and echo are normal.

**5. Remote lazydocker.** On the node, press `d` (or run `sm docker <node>`).
Expected: lazydocker opens full screen on the node, works, and `q` inside it returns to the TUI cleanly. Also try a node without lazydocker: expected notice that lazydocker is not installed and that SuperMgmt never installs it, with the install link.

**6. Ctrl-C in the child.** Press `s`. At the remote prompt, run `sleep 100` and press Ctrl-C, then press Ctrl-C once more at the empty prompt, then `exit`.
Expected: Ctrl-C reaches the remote program, not the TUI. After `exit` the TUI is still running and responsive. (Pressing Ctrl-C inside the TUI itself quits it; that is expected and is not part of this check.)

## After the six checks

- Run `sm events` and confirm each session has an end event, and no temporary `sm-kh-*` directories remain in your temporary directory: `ls "${TMPDIR:-/tmp}" | grep sm-kh-` prints nothing.
- Report anything unexpected even if the item passes.

## Results

Fill in one row per terminal. Use `pass`, `fail` or `n/a`, and describe any failure under the table.

| Item | macOS Terminal.app | macOS iTerm2 | Linux (terminal: ______) |
|---|---|---|---|
| 1 Shell opens, `exit` returns to an intact TUI | | | |
| 2 Resize in the shell, layout correct after return | | | |
| 3 Nonzero exit code shown | | | |
| 4 Mouse scroll and keys work after return | | | |
| 5 Remote lazydocker opens and returns cleanly | | | |
| 6 Ctrl-C in the child does not kill the TUI | | | |

- Date and `sm version` output:
- OS and terminal versions:
- Node OS and OpenSSH versions:
- Failures and notes:
