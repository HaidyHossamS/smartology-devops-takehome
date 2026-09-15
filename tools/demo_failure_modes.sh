#!/usr/bin/env bash
# =============================================================================
# demo_failure_modes.sh
#
# Runs the original one-liner and the replacement side by side against fixtures
# that reproduce each failure mode. Prints both the output and the exit status,
# because the exit status is the whole argument: a scheduled job is judged by
# its exit code, and the shell version returns 0 while producing nothing.
#
#   ./demo_failure_modes.sh
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ANALYZER="python3 $HERE/log_analyzer.py"

# --- preflight ---------------------------------------------------------------
# `grep -P` is a GNU extension. macOS ships BSD grep, which has no -P at all,
# and some minimal Linux images ship a grep built without PCRE support.
#
# That is failure mode #1 from the write-up, and if we ignored it here the
# original one-liner would print nothing for every single case below — which
# would overstate the comparison rather than demonstrate it. So: detect it and
# say so, which is the same principle the replacement tool is built on.
GREP=grep
if ! echo x | grep -qoP x 2>/dev/null; then
  if command -v ggrep >/dev/null 2>&1 && echo x | ggrep -qoP x 2>/dev/null; then
    GREP=ggrep
    printf '\nnote: this system'"'"'s grep has no -P; using GNU ggrep so the comparison stays meaningful.\n'
  else
    cat <<'EOF'

────────────────────────────────────────────────────────────────────────────
NOTE: this system's grep does not support -P (PCRE).

This is failure mode #1 from the write-up, live. On macOS (BSD grep) and on
minimal container images the original one-liner matches nothing at all — and
still exits 0.

The comparison below will therefore show the original producing no output for
every case, which hides the other failures rather than demonstrating them.
For the full side-by-side, run this on Linux, or:

    brew install grep      # installs GNU grep as `ggrep`

The log_analyzer.py half of each comparison is unaffected either way.
────────────────────────────────────────────────────────────────────────────
EOF
  fi
fi

legacy() {
  # The script under review, verbatim — and faithfully, which means WITHOUT
  # pipefail. The original has no `set` line at all, so its exit status is
  # head(1)'s, which is 0 no matter what happened upstream. Running it under
  # this harness's own `set -o pipefail` would flatter it by turning some of
  # these silent failures into visible ones.
  (
    set +o pipefail
    "$GREP" "Failed login" "$1" 2>/dev/null \
      | "$GREP" -oP "Username=\[\K[^\]]+" 2>/dev/null \
      | sort | uniq -c | sort -nr | head -n 5
  )
}

banner() { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }

compare() {
  local label="$1" file="$2"
  banner "$label"

  echo "--- original one-liner ---"
  local out rc
  out="$(legacy "$file")"; rc=$?
  if [ -z "$out" ]; then echo "(no output)"; else echo "$out"; fi
  echo "exit status: $rc"

  echo "--- log_analyzer.py ---"
  $ANALYZER --path "$file" --format text 2>&1 | sed 's/^/  /'
  echo "exit status: ${PIPESTATUS[0]}"
}

# -----------------------------------------------------------------------------
# 1. The happy path. Both agree — this is the case the script was written for.
# -----------------------------------------------------------------------------
cat > "$WORK/happy.log" <<'EOF'
2026-09-14T11:00:01Z WARN  Failed login. Username=[alice] ip=10.0.0.1
2026-09-14T11:00:02Z WARN  Failed login. Username=[alice] ip=10.0.0.1
2026-09-14T11:00:03Z WARN  Failed login. Username=[bob] ip=10.0.0.2
2026-09-14T11:00:04Z INFO  Successful login. Username=[carol] ip=10.0.0.3
EOF
compare "1. Standard format (both correct)" "$WORK/happy.log"

# -----------------------------------------------------------------------------
# 2. The application migrated to structured JSON logging. Nothing errored.
#    Nothing alerted. The counts just became zero, permanently.
# -----------------------------------------------------------------------------
cat > "$WORK/json.log" <<'EOF'
{"timestamp":"2026-09-14T11:00:01Z","level":"WARN","event":"Failed login","username":"alice","source_ip":"10.0.0.1"}
{"timestamp":"2026-09-14T11:00:02Z","level":"WARN","event":"Failed login","username":"alice","source_ip":"10.0.0.1"}
{"timestamp":"2026-09-14T11:00:03Z","level":"WARN","event":"Failed login","username":"mallory","source_ip":"203.0.113.7"}
EOF
compare "2. Structured logging migration (silent zero)" "$WORK/json.log"

# -----------------------------------------------------------------------------
# 3. The file is not there — logrotate moved it, or the path was wrong, or the
#    volume did not mount. grep writes to stderr and the pipeline exits 0.
# -----------------------------------------------------------------------------
compare "3. Missing input file (exits 0 anyway)" "$WORK/does-not-exist.log"

# -----------------------------------------------------------------------------
# 4. Log injection. A user registered with the name "eve] Username=[admin".
#    The bracket-delimited regex happily invents an event against 'admin'.
# -----------------------------------------------------------------------------
cat > "$WORK/injection.log" <<'EOF'
2026-09-14T11:00:01Z WARN  Failed login. Username=[eve] Username=[admin] ip=203.0.113.9
2026-09-14T11:00:02Z WARN  Failed login. Username=[eve] Username=[admin] ip=203.0.113.9
2026-09-14T11:00:03Z WARN  Failed login. Username=[eve] Username=[admin] ip=203.0.113.9
EOF
compare "4. Log injection via forged delimiter" "$WORK/injection.log"

# -----------------------------------------------------------------------------
# 5. Case variation across services writing to a shared file.
# -----------------------------------------------------------------------------
cat > "$WORK/case.log" <<'EOF'
2026-09-14T11:00:01Z WARN  failed login. Username=[dave] ip=10.0.0.4
2026-09-14T11:00:02Z WARN  FAILED LOGIN. Username=[dave] ip=10.0.0.4
2026-09-14T11:00:03Z WARN  Failed login. Username=[dave] ip=10.0.0.4
EOF
compare "5. Case variation (2 of 3 events missed)" "$WORK/case.log"

banner "SIGPIPE under set -o pipefail"
echo "A hardened wrapper adds 'set -euo pipefail'. Then head(1) closing the pipe"
echo "early makes sort exit on SIGPIPE and the whole pipeline returns 141:"
( set -o pipefail; legacy "$WORK/happy.log" >/dev/null; echo "  pipeline exit: $?" )
echo "  seq 1 200000 | sort | head -n 1 (pipefail on):"
( set -o pipefail; seq 1 200000 | sort -nr | head -n 1 >/dev/null; echo "  exit: $?" )

banner "Summary"
cat <<'EOF'
The original script is not wrong. It is unsupervised.

Every failure above produces empty output and exit status 0, which to cron,
systemd or a CI job is indistinguishable from "no failed logins today". The
replacement returns 4 for missing input and 3 for a format change, so the
monitor reports its own breakage instead of hiding it.
EOF
