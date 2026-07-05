# demo.tape — VHS script for the statedrift README demo.
#
# Renders the init → drift → diff → verify → tamper-catch story to a GIF.
# Every command below runs for real; nothing is faked. The staged drift
# (enable IP forwarding + add a user) is undone in the hidden cleanup block,
# and the whole thing runs against a throwaway store in /tmp so it is safe
# and repeatable.
#
# Requirements: vhs, ffmpeg, ttyd, and `statedrift` on PATH.
# Run as ROOT (sysctl -w and useradd need it) so no sudo password prompt
# stalls the recording:
#
#     sudo vhs demo.tape        # produces demo.gif
#
# After recording, update the static transcript in README.md to match the
# real output (snapshot count, hashes, exact lines).

Output demo.gif

Require statedrift

Set Shell "zsh"
Set FontSize 20
Set Width 1220
Set Height 760
Set Padding 22
Set TypingSpeed 55ms
Set Theme "Catppuccin Mocha"
# Optional polish — a fake window title bar looks good in a README:
# Set WindowBar Colorful

# --- hidden setup: isolated, repeatable store + known-clean starting state ---
Hide
# Muted-grey commands, blue comments (zsh-syntax-highlighting). VHS starts zsh
# with rc files skipped, so this config is sourced explicitly here. See
# Dockerfile.demo (/etc/statedrift-demo.zsh). Harmless/no-op under bash.
Type "source /etc/statedrift-demo.zsh 2>/dev/null" Enter
Type "export STATEDRIFT_STORE=/tmp/statedrift-demo" Enter
Type "rm -rf $STATEDRIFT_STORE" Enter
Type "sysctl -qw net.ipv4.ip_forward=0 2>/dev/null" Enter
Type "userdel -r backdoor 2>/dev/null" Enter
Type "clear" Enter
Show

# --- scene 1: record the genesis snapshot (the chain root) ---
Type "statedrift init" Sleep 500ms Enter
Sleep 2.5s

# --- scene 1b: a routine baseline snapshot while the box is still healthy ---
Type "# a routine snapshot while everything is still healthy:" Sleep 400ms Enter
Sleep 900ms
Type "statedrift snap" Sleep 400ms Enter
Sleep 2s

Type "# ...an hour later, an intruder quietly changes the box:" Sleep 400ms Enter
Sleep 900ms
Type "sysctl -w net.ipv4.ip_forward=1     # turn the host into a router" Sleep 400ms Enter
Sleep 1.2s
Type "useradd -m -s /bin/bash backdoor    # add themselves an account" Sleep 400ms Enter
Sleep 1.5s

# --- scene 2: snapshot, then diff surfaces exactly what changed ---
Type "statedrift snap" Sleep 400ms Enter
Sleep 1.8s
Type "statedrift diff HEAD~1 HEAD" Sleep 500ms Enter
Sleep 3.8s

# --- scene 2b: a diff shows everything; analyze flags what's dangerous ---
Type "# a diff lists every change; analyze says which ones are dangerous:" Sleep 400ms Enter
Sleep 900ms
Type "statedrift analyze" Sleep 500ms Enter
Sleep 4.5s

# --- scene 3: the hash chain proves nothing was forged ---
Type "statedrift verify" Sleep 500ms Enter
Sleep 3s

Type "# now an attacker edits an old snapshot to erase the evidence..." Sleep 400ms Enter
Sleep 1.2s
# Hide the plumbing; show only the result. This mutates a real captured field
# (host.kernel) in the genesis snapshot, so its hash no longer matches the
# prev_hash recorded by the next snapshot — a genuine chain break.
Hide
Type `FIRST=$(ls -1 $STATEDRIFT_STORE/chain/*/*.json | head -1)` Enter
Type `sed -i 's/\("kernel": *"\)/\1X/' "$FIRST"` Enter
Show
Type "statedrift verify" Sleep 500ms Enter
# Long hold on this final "verify" frame (the tamper-catch payoff) so the reader
# can finish reading before the GIF loops back to the start. This Sleep must come
# BEFORE the hidden cleanup: cleanup commands execute and scroll the terminal
# even while hidden, so holding after them would sit on cleanup residue instead.
Sleep 5s

# --- hidden cleanup: undo the staged drift and remove the demo store. Runs
# off-camera; note there is deliberately NO `Show` afterward, so the GIF's last
# recorded frame stays on the verify payoff rather than the cleanup commands. ---
Hide
Type "sysctl -qw net.ipv4.ip_forward=0 2>/dev/null" Enter
Type "userdel -r backdoor 2>/dev/null" Enter
Type "rm -rf $STATEDRIFT_STORE" Enter
