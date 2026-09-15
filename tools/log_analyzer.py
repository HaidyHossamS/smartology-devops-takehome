#!/usr/bin/env python3
"""
log_analyzer.py — a failed-login analyser that is safe to run unattended.

This replaces:

    grep "Failed login" app.log | grep -oP "Username=\\[\\K[^\\]]+" \\
      | sort | uniq -c | sort -nr | head -n 5

The pipeline above is fine as something an engineer types once while looking at
the output. It is not safe as a scheduled job, and the reason is not that it is
slow or ugly. It is that every one of its failure modes is silent:

  * grep without -P support         -> prints nothing, looks like "no failures"
  * log format changed              -> matches nothing, looks like "no failures"
  * app.log missing or rotated away -> stderr nobody reads, exit status 0
  * sort spilling to a full /tmp    -> partial results, no indication
  * SIGPIPE from `head`             -> exit 141 under `set -o pipefail`

A monitoring tool that cannot tell "nothing bad happened" apart from "I am
broken" is worse than no monitoring tool, because it manufactures confidence.
Everything below exists to make that distinction impossible to miss.

Design constraints, deliberately chosen:

  * Standard library only. It has to run on the legacy hosts too, without pip,
    without a venv, without network access. Python 3.8+.
  * Constant memory in log size. Streaming, never readlines().
  * Bounded memory in cardinality, with an explicit guard rather than an OOM.
  * Every abnormal condition is a distinct, documented exit code.
  * Machine-readable output by default, so it composes into CloudWatch,
    Prometheus or a CI assertion without anyone parsing human text.

Usage:
    log_analyzer.py --path '/var/log/app/app.log*' --top 5 --window 15m
    log_analyzer.py --path app.log --format prometheus --fail-over 100
    log_analyzer.py --path 'logs/*.gz' --format emf --checkpoint /var/lib/la.json

Exit codes:
    0  OK
    2  THRESHOLD_BREACH   a user exceeded --fail-over failures in the window
    3  FORMAT_DRIFT       lines were read but none parsed; the schema moved
    4  NO_INPUT           nothing matched --path, or nothing was readable
    5  CARDINALITY_GUARD  distinct-user count exceeded the memory guard
    1  unexpected internal error (stack trace on stderr)
"""

from __future__ import annotations

import argparse
import glob
import gzip
import heapq
import json
import os
import re
import stat
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

__version__ = "1.2.0"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_THRESHOLD = 2
EXIT_FORMAT_DRIFT = 3
EXIT_NO_INPUT = 4
EXIT_CARDINALITY = 5


# =============================================================================
# Parsing
# =============================================================================

# The legacy line format, e.g.
#   2026-09-14T11:02:31Z WARN  Failed login. Username=[alice] ip=10.0.4.12
#
# Two things the original one-liner got wrong and this does not:
#
#   1. Case. "Failed login", "failed login" and "FAILED_LOGIN" all appear in
#      real codebases, often from different services writing to the same file.
#   2. Anchoring. `[^\]]+` happily matches across a forged bracket. A user who
#      registers the name "alice] Username=[admin" can inject a second
#      apparent event into the log and skew whatever reads it. We validate the
#      extracted value against a username charset instead of trusting the
#      delimiter.
LEGACY_EVENT = re.compile(r"fail(?:ed|ure)[ _-]?login", re.IGNORECASE)
LEGACY_USERNAME = re.compile(r"Username=\[([^\]]*)\]")
LEGACY_SOURCE_IP = re.compile(r"\bip=([0-9a-fA-F:.]+)")

# Deliberately conservative. Anything outside this is either an attack or a
# schema change, and both are things we want to hear about rather than count.
VALID_USERNAME = re.compile(r"^[A-Za-z0-9._@+-]{1,128}$")

TIMESTAMP_PATTERNS = (
    # ISO-8601, with or without fractional seconds and with Z or offset
    re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    # Common Java/log4j default: 2026-09-14 11:02:31,123
    re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3}"),
)

JSON_EVENT_KEYS = ("event", "message", "msg", "action")
JSON_USER_KEYS = ("username", "user", "user_name", "userId", "user_id", "principal")
JSON_IP_KEYS = ("source_ip", "sourceIp", "client_ip", "remote_addr", "ip")
JSON_TIME_KEYS = ("timestamp", "time", "@timestamp", "ts", "eventTime")


@dataclass
class FailedLogin:
    username: str
    source_ip: Optional[str]
    when: Optional[datetime]
    suspicious: bool = False


def _parse_timestamp(raw: str) -> Optional[datetime]:
    """Parse a timestamp into an aware UTC datetime, or None.

    Naive timestamps are assumed UTC. That assumption is stated here rather
    than buried, because getting it wrong silently shifts every time window by
    the host's offset — which is exactly the kind of bug that only appears
    after a DST change.
    """
    if not raw:
        return None
    text = raw.strip().replace(",", ".")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _first_key(payload: dict, keys: Iterable[str]) -> Optional[str]:
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def parse_line(line: str) -> Tuple[bool, Optional[FailedLogin]]:
    """Parse one log line.

    Returns (recognised, event). `recognised` means "this line was in a shape I
    understand", regardless of whether it was a failed login. That distinction
    is what powers drift detection: a file full of lines we do not recognise is
    a schema change, not a quiet day.
    """
    stripped = line.strip()
    if not stripped:
        return False, None

    # Structured logging. Most teams migrate to this eventually, and the
    # migration is precisely when a regex-based monitor starts reporting zero.
    if stripped[0] == "{":
        try:
            payload = json.loads(stripped)
        except (ValueError, RecursionError):
            return False, None
        if not isinstance(payload, dict):
            return False, None

        event = _first_key(payload, JSON_EVENT_KEYS) or ""
        if not LEGACY_EVENT.search(event):
            return True, None  # understood the shape, just not a failed login

        username = _first_key(payload, JSON_USER_KEYS)
        if username is None:
            return True, None

        return True, FailedLogin(
            username=username,
            source_ip=_first_key(payload, JSON_IP_KEYS),
            when=_parse_timestamp(_first_key(payload, JSON_TIME_KEYS) or ""),
            suspicious=not VALID_USERNAME.match(username),
        )

    # Legacy plain-text format.
    if not LEGACY_EVENT.search(stripped):
        return _looks_like_a_log_line(stripped), None

    match = LEGACY_USERNAME.search(stripped)
    if not match:
        # We saw the event marker but could not find the username. That is a
        # partial schema change and it is worth surfacing separately: the old
        # script would have dropped this line without a word.
        return True, None

    username = match.group(1)
    when = None
    for pattern in TIMESTAMP_PATTERNS:
        found = pattern.search(stripped)
        if found:
            when = _parse_timestamp(found.group(1))
            break

    ip_match = LEGACY_SOURCE_IP.search(stripped)

    return True, FailedLogin(
        username=username,
        source_ip=ip_match.group(1) if ip_match else None,
        when=when,
        suspicious=not VALID_USERNAME.match(username),
    )


def _looks_like_a_log_line(text: str) -> bool:
    """Heuristic: does this look like a log line we simply had no interest in?

    Used so that a file of perfectly valid INFO lines does not trip the drift
    detector, while a file of, say, HTML or binary garbage does.
    """
    if any(pattern.search(text) for pattern in TIMESTAMP_PATTERNS):
        return True
    return bool(re.search(r"\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|SEVERE)\b", text))


# =============================================================================
# Input handling
# =============================================================================


@dataclass
class Checkpoint:
    """Remembers how far into each file we got.

    Keyed by (device, inode) rather than by path, which is what makes this
    survive log rotation correctly:

      * logrotate with `create`      -> new inode, offset resets to 0. Correct.
      * logrotate with `copytruncate`-> same inode, size < offset. We detect the
                                        truncation and restart from 0 rather
                                        than seeking past the end and reading
                                        nothing forever.
      * plain append                 -> same inode, resume from offset.

    The original script has no concept of this at all: every run rescans the
    whole file, which is both O(n) forever and double-counts every event on
    every run.
    """

    path: str
    offsets: Dict[str, int] = field(default_factory=dict)

    @staticmethod
    def key(st: os.stat_result) -> str:
        return "{}:{}".format(st.st_dev, st.st_ino)

    @classmethod
    def load(cls, path: Optional[str]) -> "Checkpoint":
        if not path:
            return cls(path="")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return cls(path=path, offsets=dict(data.get("offsets", {})))
        except (OSError, ValueError):
            # A corrupt or missing checkpoint must not stop the run. Worst case
            # we reprocess, which is safe; refusing to run is not.
            return cls(path=path)

    def save(self) -> None:
        if not self.path:
            return
        tmp = self.path + ".tmp"
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump({"version": __version__, "offsets": self.offsets}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)  # atomic; never leaves a half-written file


def discover(pattern: str) -> List[str]:
    """Expand a glob into readable regular files, newest last.

    Refuses FIFOs and character devices outright. Pointing the old script at a
    named pipe makes it block forever with no output and no error — a hang, in
    a cron job, holding a lock. Better to fail immediately and loudly.
    """
    candidates = sorted(glob.glob(pattern))
    files = []
    for candidate in candidates:
        try:
            st = os.stat(candidate)
        except OSError:
            continue
        if stat.S_ISFIFO(st.st_mode) or stat.S_ISCHR(st.st_mode):
            raise ValueError(
                "{} is a FIFO or character device. Streaming inputs are not "
                "supported: this tool is a bounded batch job by design.".format(candidate)
            )
        if not stat.S_ISREG(st.st_mode):
            continue
        if not os.access(candidate, os.R_OK):
            continue
        files.append(candidate)
    return sorted(files, key=lambda p: os.stat(p).st_mtime)


GZIP_CONSUMED = -1


def iter_lines(
    paths: List[str],
    checkpoint: Checkpoint,
    deadline: Optional[float] = None,
) -> Iterator[str]:
    """Stream lines from every file, resuming from the checkpoint.

    Memory is constant: one line at a time, never a list and never a sort.
    The original `sort | uniq -c` materialises the entire extracted column,
    spilling to /tmp when it exceeds its buffer, so a 40GB log with a
    high-cardinality username column can fill the disk and take the host down
    with it. Counting in a hash map is O(n) time and O(distinct) memory
    instead of O(n log n) time and O(n) disk.

    Files are read in binary and decoded here rather than through a text-mode
    handle, because seeking a TextIOWrapper to an arbitrary byte offset is not
    supported — its seek() only accepts opaque cookies from its own tell().
    Doing it by hand is the difference between a checkpoint that works and one
    that silently resumes in the wrong place.
    """
    for path in paths:
        try:
            st = os.stat(path)
        except OSError:
            continue

        key = Checkpoint.key(st)
        start = checkpoint.offsets.get(key, 0)
        is_gzip = path.endswith(".gz")

        if is_gzip:
            # Rotated .gz files are immutable once written, so there is no
            # point re-reading one we have already fully consumed.
            if start == GZIP_CONSUMED:
                continue
            start = 0
        elif start > st.st_size:
            # Truncated in place (logrotate copytruncate): same inode, smaller
            # file. Seeking to the old offset would land past EOF and read
            # nothing, forever, while reporting success. Start over instead.
            start = 0

        try:
            handle = gzip.open(path, "rb") if is_gzip else open(path, "rb")
        except OSError:
            continue

        with handle:
            if start:
                try:
                    handle.seek(start)
                except OSError:
                    start = 0
                    handle.seek(0)

            for raw in handle:
                # errors="replace" rather than "strict": one malformed byte in
                # a 40GB file must not abort the run. Counting 99.9999% of the
                # events beats counting none of them.
                yield raw.decode("utf-8", errors="replace")

                if deadline is not None and time.monotonic() > deadline:
                    # Record where we stopped so the next run resumes here
                    # rather than restarting and timing out at the same point
                    # forever.
                    if not is_gzip:
                        checkpoint.offsets[key] = _tell(handle, st.st_size)
                    raise TimeoutError(
                        "exceeded --max-seconds while reading {}; progress checkpointed".format(path)
                    )

            checkpoint.offsets[key] = GZIP_CONSUMED if is_gzip else _tell(handle, st.st_size)


def _tell(handle, fallback: int) -> int:
    try:
        return handle.tell()
    except (OSError, AttributeError):
        return fallback


# =============================================================================
# Analysis
# =============================================================================


@dataclass
class Report:
    top_users: List[Tuple[str, int]]
    top_source_ips: List[Tuple[str, int]]
    lines_read: int = 0
    lines_recognised: int = 0
    events_matched: int = 0
    events_in_window: int = 0
    events_without_timestamp: int = 0
    suspicious_usernames: int = 0
    distinct_users: int = 0
    files: List[str] = field(default_factory=list)
    window_seconds: Optional[int] = None
    duration_seconds: float = 0.0
    drift_detected: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema": "smartology.failed_logins/v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "window_seconds": self.window_seconds,
            "top_users": [{"username": u, "failures": c} for u, c in self.top_users],
            "top_source_ips": [{"source_ip": i, "failures": c} for i, c in self.top_source_ips],
            "counters": {
                "lines_read": self.lines_read,
                "lines_recognised": self.lines_recognised,
                "events_matched": self.events_matched,
                "events_in_window": self.events_in_window,
                "events_without_timestamp": self.events_without_timestamp,
                "suspicious_usernames": self.suspicious_usernames,
                "distinct_users": self.distinct_users,
            },
            "files": self.files,
            "drift_detected": self.drift_detected,
            "duration_seconds": round(self.duration_seconds, 4),
            "notes": self.notes,
        }


def analyse(
    lines: Iterable[str],
    top_n: int = 5,
    window: Optional[timedelta] = None,
    now: Optional[datetime] = None,
    max_distinct_users: int = 500_000,
) -> Report:
    """Count failed logins per user over a bounded time window.

    Two counting decisions worth defending:

    Time window. The original script counts every failure in the file, for all
    time. An incident from three months ago therefore dominates the top 5
    forever, and a monitor built on it reports the same five names every day
    regardless of what is happening now. A window turns a historical trivia
    query into an operational signal.

    Cardinality guard. A credential-stuffing run against randomly generated
    usernames produces unbounded distinct keys. An in-memory Counter grows
    linearly with that, and the process is OOM-killed — during exactly the
    incident you built the tool to detect. We stop counting and report instead.
    """
    started = time.monotonic()
    reference = now or datetime.now(timezone.utc)
    cutoff = reference - window if window else None

    user_counts: Counter = Counter()
    ip_counts: Counter = Counter()
    report = Report(top_users=[], top_source_ips=[])
    report.window_seconds = int(window.total_seconds()) if window else None

    for line in lines:
        report.lines_read += 1
        recognised, event = parse_line(line)
        if recognised:
            report.lines_recognised += 1
        if event is None:
            continue

        report.events_matched += 1

        if event.suspicious:
            report.suspicious_usernames += 1
            # Counted under a single sentinel key rather than under the
            # attacker-chosen string. A username containing "]" or a newline is
            # a log-injection attempt, and echoing it into a dashboard or an
            # alert body is how the injection lands.
            user_counts["<invalid-username>"] += 1
            continue

        if cutoff is not None:
            if event.when is None:
                report.events_without_timestamp += 1
                continue
            if event.when < cutoff:
                continue

        report.events_in_window += 1
        user_counts[event.username] += 1
        if event.source_ip:
            ip_counts[event.source_ip] += 1

        if len(user_counts) > max_distinct_users:
            report.notes.append(
                "cardinality guard tripped at {} distinct usernames after {} lines; "
                "this pattern is consistent with credential stuffing against "
                "generated usernames".format(max_distinct_users, report.lines_read)
            )
            report.distinct_users = len(user_counts)
            report.duration_seconds = time.monotonic() - started
            report.top_users = _top(user_counts, top_n)
            report.top_source_ips = _top(ip_counts, top_n)
            return report

    report.distinct_users = len(user_counts)
    report.top_users = _top(user_counts, top_n)
    report.top_source_ips = _top(ip_counts, top_n)
    report.duration_seconds = time.monotonic() - started

    # Drift detection. If we read a meaningful number of lines and understood
    # essentially none of them, the log format has moved and every number above
    # is a lie. Say so rather than printing a confident zero.
    if report.lines_read >= 50 and report.lines_recognised / report.lines_read < 0.10:
        report.drift_detected = True
        report.notes.append(
            "recognised only {}/{} lines. The log format has probably changed; "
            "treat the counts above as unreliable".format(
                report.lines_recognised, report.lines_read
            )
        )

    if report.events_without_timestamp:
        report.notes.append(
            "{} failed-login events had no parseable timestamp and were excluded "
            "from the window".format(report.events_without_timestamp)
        )

    return report


def _top(counts: Counter, n: int) -> List[Tuple[str, int]]:
    """Top N, with a deterministic tie-break.

    `sort -nr | head -5` breaks ties by whatever order the previous sort
    happened to produce, so two runs over the same data can disagree about who
    is fifth. Sorting by (-count, name) makes the output reproducible, which
    matters the moment anything downstream diffs it.
    """
    if n <= 0:
        return []
    return heapq.nsmallest(n, counts.items(), key=lambda kv: (-kv[1], kv[0]))


# =============================================================================
# Output
# =============================================================================


def render(report: Report, fmt: str, service: str, environment: str) -> str:
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2)

    if fmt == "prometheus":
        lines = [
            "# HELP failed_logins_total Failed login attempts per user in the window.",
            "# TYPE failed_logins_total gauge",
        ]
        for username, count in report.top_users:
            lines.append(
                'failed_logins_total{{service="{}",env="{}",username="{}"}} {}'.format(
                    service, environment, _escape(username), count
                )
            )
        lines += [
            "# HELP failed_login_analyzer_lines_read_total Lines inspected on the last run.",
            "# TYPE failed_login_analyzer_lines_read_total gauge",
            "failed_login_analyzer_lines_read_total{{service=\"{}\"}} {}".format(
                service, report.lines_read
            ),
            "# HELP failed_login_analyzer_drift Whether the log format appears to have changed.",
            "# TYPE failed_login_analyzer_drift gauge",
            "failed_login_analyzer_drift{{service=\"{}\"}} {}".format(
                service, 1 if report.drift_detected else 0
            ),
            "# HELP failed_login_analyzer_duration_seconds Wall time of the last run.",
            "# TYPE failed_login_analyzer_duration_seconds gauge",
            "failed_login_analyzer_duration_seconds{{service=\"{}\"}} {:.4f}".format(
                service, report.duration_seconds
            ),
        ]
        return "\n".join(lines) + "\n"

    if fmt == "emf":
        # CloudWatch Embedded Metric Format: write one JSON blob to stdout and
        # CloudWatch extracts real metrics from it. No PutMetricData call, no
        # extra IAM permission, no API latency in the hot path.
        return json.dumps(
            {
                "_aws": {
                    "Timestamp": int(time.time() * 1000),
                    "CloudWatchMetrics": [
                        {
                            "Namespace": "Smartology/Security",
                            "Dimensions": [["Service", "Environment"]],
                            "Metrics": [
                                {"Name": "FailedLogins", "Unit": "Count"},
                                {"Name": "DistinctFailedUsers", "Unit": "Count"},
                                {"Name": "LogFormatDrift", "Unit": "Count"},
                                {"Name": "SuspiciousUsernames", "Unit": "Count"},
                            ],
                        }
                    ],
                },
                "Service": service,
                "Environment": environment,
                "FailedLogins": report.events_in_window,
                "DistinctFailedUsers": report.distinct_users,
                "LogFormatDrift": 1 if report.drift_detected else 0,
                "SuspiciousUsernames": report.suspicious_usernames,
                "TopUsers": [{"username": u, "failures": c} for u, c in report.top_users],
            }
        )

    # Human-readable. Last, because it is the least important consumer.
    width = max([len(u) for u, _ in report.top_users] + [8])
    out = ["Top {} users by failed logins".format(len(report.top_users))]
    if report.window_seconds:
        out.append("Window: last {}s".format(report.window_seconds))
    out.append("-" * (width + 12))
    for username, count in report.top_users:
        out.append("{:>8}  {}".format(count, username.ljust(width)))
    out.append("-" * (width + 12))
    out.append(
        "{} lines read, {} recognised, {} events in window".format(
            report.lines_read, report.lines_recognised, report.events_in_window
        )
    )
    for note in report.notes:
        out.append("NOTE: " + note)
    return "\n".join(out) + "\n"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "")


def parse_window(text: Optional[str]) -> Optional[timedelta]:
    if not text:
        return None
    match = re.fullmatch(r"(\d+)([smhd])", text.strip())
    if not match:
        raise argparse.ArgumentTypeError(
            "window must look like 90s, 15m, 6h or 7d (got {!r})".format(text)
        )
    amount, unit = int(match.group(1)), match.group(2)
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]: amount})


# =============================================================================
# CLI
# =============================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Count failed logins per user, safely enough to run unattended.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--path", required=True, help="File or glob, e.g. '/var/log/app.log*'")
    parser.add_argument("--top", type=int, default=5, help="How many users to report (default 5)")
    parser.add_argument(
        "--window",
        default=None,
        help="Only count events within this window, e.g. 15m. Without it, counts are all-time.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "prometheus", "emf", "text"),
        default="json",
        help="Output format (default json)",
    )
    parser.add_argument("--service", default="legacy-app", help="Service label for metrics")
    parser.add_argument("--environment", default=os.environ.get("ENVIRONMENT", "unknown"))
    parser.add_argument(
        "--checkpoint",
        default=None,
        help="Checkpoint file. With it, each run only reads data appended since the last run.",
    )
    parser.add_argument(
        "--fail-over",
        type=int,
        default=None,
        help="Exit %d if any user exceeds this many failures in the window." % EXIT_THRESHOLD,
    )
    parser.add_argument(
        "--max-seconds",
        type=float,
        default=None,
        help="Wall-clock budget. Exceeding it checkpoints progress and exits non-zero rather than "
        "running until the next invocation overlaps this one.",
    )
    parser.add_argument(
        "--max-distinct-users",
        type=int,
        default=500_000,
        help="Cardinality guard. Above this, stop counting and report instead of being OOM-killed.",
    )
    parser.add_argument(
        "--allow-drift",
        action="store_true",
        help="Do not exit %d when the log format appears to have changed. Off by default: "
        "silently reporting zero is the failure mode this tool exists to prevent." % EXIT_FORMAT_DRIFT,
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        window = parse_window(args.window)
    except argparse.ArgumentTypeError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR

    try:
        paths = discover(args.path)
    except ValueError as exc:
        print("input error: {}".format(exc), file=sys.stderr)
        return EXIT_NO_INPUT

    if not paths:
        # The single most important difference from the shell version. `grep`
        # on a missing file writes to stderr, the pipeline still exits 0, and
        # cron records a success. Here, no input is an explicit failure.
        print(
            "no readable files matched {!r}. Refusing to report zero failures from zero "
            "files: that is indistinguishable from a healthy system.".format(args.path),
            file=sys.stderr,
        )
        return EXIT_NO_INPUT

    checkpoint = Checkpoint.load(args.checkpoint)
    deadline = time.monotonic() + args.max_seconds if args.max_seconds else None

    try:
        report = analyse(
            iter_lines(paths, checkpoint, deadline),
            top_n=args.top,
            window=window,
            max_distinct_users=args.max_distinct_users,
        )
    except TimeoutError as exc:
        checkpoint.save()
        print("timeout: {}".format(exc), file=sys.stderr)
        return EXIT_ERROR

    report.files = paths
    checkpoint.save()

    sys.stdout.write(render(report, args.format, args.service, args.environment))

    if report.notes and any("cardinality guard" in note for note in report.notes):
        return EXIT_CARDINALITY

    if report.drift_detected and not args.allow_drift:
        print(
            "FORMAT_DRIFT: recognised {}/{} lines. Counts are unreliable.".format(
                report.lines_recognised, report.lines_read
            ),
            file=sys.stderr,
        )
        return EXIT_FORMAT_DRIFT

    if args.fail_over is not None and report.top_users:
        worst_user, worst_count = report.top_users[0]
        if worst_count > args.fail_over:
            print(
                "THRESHOLD_BREACH: {} had {} failed logins (limit {})".format(
                    worst_user, worst_count, args.fail_over
                ),
                file=sys.stderr,
            )
            return EXIT_THRESHOLD

    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
