#!/usr/bin/env python3
"""
Tests for log_analyzer.

stdlib `unittest`, not pytest, for the same reason the analyser itself is
stdlib-only: this has to run on the legacy hosts and in a minimal CI image
without a pip install step.

Every test below maps to a specific way the original shell pipeline fails.
That is the point of the suite — not line coverage, but a standing proof that
each known failure mode is handled, so the next person to touch the parser
finds out immediately if they reintroduce one.

    python3 -m unittest discover -s tools -v
"""

import gzip
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import log_analyzer as la  # noqa: E402

NOW = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)


def line(minutes_ago=0, user="alice", event="Failed login", ip="10.0.0.1"):
    ts = (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return "{} WARN  {}. Username=[{}] ip={}\n".format(ts, event, user, ip)


class ParsingTests(unittest.TestCase):
    """Bash failure mode: the regex is a single hardcoded shape."""

    def test_standard_line(self):
        recognised, event = la.parse_line(line(user="alice"))
        self.assertTrue(recognised)
        self.assertEqual(event.username, "alice")
        self.assertEqual(event.source_ip, "10.0.0.1")

    def test_case_insensitive_event_marker(self):
        # grep "Failed login" misses every one of these.
        for variant in ("failed login", "FAILED LOGIN", "Failed_Login", "failure-login"):
            with self.subTest(variant=variant):
                _, event = la.parse_line(line(event=variant))
                self.assertIsNotNone(event, "missed variant: " + variant)

    def test_json_structured_logging(self):
        # The migration to structured logging is the single most likely reason
        # the original script would start reporting zero failures forever.
        payload = json.dumps(
            {
                "timestamp": "2026-09-14T11:59:00Z",
                "level": "WARN",
                "event": "Failed login",
                "username": "bob",
                "source_ip": "10.0.0.9",
            }
        )
        recognised, event = la.parse_line(payload)
        self.assertTrue(recognised)
        self.assertEqual(event.username, "bob")
        self.assertEqual(event.source_ip, "10.0.0.9")

    def test_json_alternate_key_names(self):
        payload = json.dumps({"msg": "failed login", "user": "carol", "ts": "2026-09-14T11:59:00Z"})
        _, event = la.parse_line(payload)
        self.assertEqual(event.username, "carol")

    def test_informational_lines_are_recognised_but_not_counted(self):
        recognised, event = la.parse_line("2026-09-14T11:00:00Z INFO  Successful login. Username=[dave]")
        self.assertTrue(recognised, "a valid INFO line must not look like drift")
        self.assertIsNone(event)

    def test_event_marker_without_username_is_not_silently_dropped(self):
        recognised, event = la.parse_line("2026-09-14T11:00:00Z WARN Failed login for an unknown principal")
        self.assertTrue(recognised)
        self.assertIsNone(event)


class LogInjectionTests(unittest.TestCase):
    """Bash failure mode: `[^\\]]+` trusts a delimiter an attacker controls."""

    def test_forged_bracket_does_not_create_a_phantom_user(self):
        raw = "2026-09-14T11:00:00Z WARN Failed login. Username=[alice] Username=[admin]\n"
        _, event = la.parse_line(raw)
        # First match wins; the injected second field never becomes its own count.
        self.assertEqual(event.username, "alice")

    def test_hostile_username_is_bucketed_not_echoed(self):
        raw = "2026-09-14T11:00:00Z WARN Failed login. Username=[<script>alert(1)</script>]\n"
        _, event = la.parse_line(raw)
        self.assertTrue(event.suspicious)

        report = la.analyse([raw], now=NOW)
        names = [u for u, _ in report.top_users]
        self.assertIn("<invalid-username>", names)
        self.assertNotIn("<script>alert(1)</script>", names)
        self.assertEqual(report.suspicious_usernames, 1)

    def test_empty_username_is_suspicious(self):
        _, event = la.parse_line("2026-09-14T11:00:00Z WARN Failed login. Username=[]\n")
        self.assertTrue(event.suspicious)


class WindowingTests(unittest.TestCase):
    """Bash failure mode: counts are all-time, so an old incident dominates forever."""

    def test_window_excludes_stale_events(self):
        lines = [line(minutes_ago=5, user="recent")] + [
            line(minutes_ago=5000, user="ancient") for _ in range(50)
        ]
        report = la.analyse(lines, window=timedelta(minutes=15), now=NOW)
        self.assertEqual(report.top_users, [("recent", 1)])
        self.assertEqual(report.events_in_window, 1)

    def test_without_window_everything_counts(self):
        lines = [line(minutes_ago=5, user="recent")] + [
            line(minutes_ago=5000, user="ancient") for _ in range(50)
        ]
        report = la.analyse(lines, now=NOW)
        self.assertEqual(report.top_users[0], ("ancient", 50))

    def test_undated_events_are_excluded_and_reported(self):
        lines = ["WARN Failed login. Username=[nodate]\n"] * 3
        report = la.analyse(lines, window=timedelta(minutes=15), now=NOW)
        self.assertEqual(report.events_without_timestamp, 3)
        self.assertEqual(report.events_in_window, 0)
        self.assertTrue(any("no parseable timestamp" in n for n in report.notes))

    def test_naive_and_offset_timestamps_both_parse(self):
        for raw in (
            "2026-09-14 11:59:00,123 WARN Failed login. Username=[x]",
            "2026-09-14T11:59:00+00:00 WARN Failed login. Username=[x]",
            "2026-09-14T12:59:00+01:00 WARN Failed login. Username=[x]",
        ):
            with self.subTest(raw=raw):
                report = la.analyse([raw], window=timedelta(minutes=15), now=NOW)
                self.assertEqual(report.events_in_window, 1, raw)


class DriftDetectionTests(unittest.TestCase):
    """Bash failure mode: a schema change silently prints nothing."""

    def test_unparseable_file_is_flagged_not_reported_as_zero(self):
        lines = ["<html><body>502 Bad Gateway</body></html>\n"] * 100
        report = la.analyse(lines, now=NOW)
        self.assertTrue(report.drift_detected)
        self.assertEqual(report.top_users, [])

    def test_a_genuinely_quiet_log_is_not_flagged_as_drift(self):
        # This is the test that stops drift detection from becoming a
        # false-positive generator. A healthy log with no failures must be
        # clearly distinguishable from a broken parser.
        lines = [
            "2026-09-14T11:00:00Z INFO Successful login. Username=[u{}]\n".format(i)
            for i in range(100)
        ]
        report = la.analyse(lines, now=NOW)
        self.assertFalse(report.drift_detected)
        self.assertEqual(report.top_users, [])

    def test_small_files_do_not_trip_the_detector(self):
        report = la.analyse(["garbage\n"] * 5, now=NOW)
        self.assertFalse(report.drift_detected, "too little evidence to call drift")


class CardinalityTests(unittest.TestCase):
    """Bash failure mode: unbounded sort input during credential stuffing."""

    def test_guard_trips_instead_of_exhausting_memory(self):
        lines = (line(user="user%06d" % i) for i in range(5000))
        report = la.analyse(lines, max_distinct_users=1000, now=NOW)
        self.assertTrue(any("cardinality guard" in n for n in report.notes))
        self.assertGreater(report.distinct_users, 1000)

    def test_normal_cardinality_does_not_trip(self):
        report = la.analyse([line(user="u%d" % (i % 20)) for i in range(500)], now=NOW)
        self.assertEqual(report.notes, [])


class OrderingTests(unittest.TestCase):
    """Bash failure mode: `sort -nr | head` breaks ties nondeterministically."""

    def test_ties_break_alphabetically_and_reproducibly(self):
        lines = [line(user=u) for u in ("zoe", "adam", "mary")]
        first = la.analyse(lines, top_n=3, now=NOW).top_users
        second = la.analyse(list(reversed(lines)), top_n=3, now=NOW).top_users
        self.assertEqual(first, second)
        self.assertEqual([u for u, _ in first], ["adam", "mary", "zoe"])

    def test_top_n_respects_ordering_by_count(self):
        lines = [line(user="heavy")] * 10 + [line(user="light")] * 2
        report = la.analyse(lines, top_n=1, now=NOW)
        self.assertEqual(report.top_users, [("heavy", 10)])


class FileHandlingTests(unittest.TestCase):
    """Bash failure modes: rotation, compression, missing files, FIFOs."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, name, content, compress=False):
        path = os.path.join(self.dir, name)
        if compress:
            with gzip.open(path, "wt", encoding="utf-8") as fh:
                fh.write(content)
        else:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
        return path

    def test_rotated_and_compressed_files_are_included(self):
        # `grep ... app.log` reads exactly one file and misses the rotations,
        # so the counts silently reset every time logrotate runs.
        self._write("app.log", line(user="today"))
        self._write("app.log.1", line(user="yesterday"))
        self._write("app.log.2.gz", line(user="older"), compress=True)

        paths = la.discover(os.path.join(self.dir, "app.log*"))
        self.assertEqual(len(paths), 3)

        report = la.analyse(la.iter_lines(paths, la.Checkpoint(path="")), now=NOW)
        self.assertEqual(report.events_matched, 3)

    def test_fifo_is_refused_rather_than_hanging(self):
        fifo = os.path.join(self.dir, "app.log")
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            la.discover(fifo)

    def test_missing_input_exits_nonzero(self):
        # The headline fix. The shell version exits 0 here and cron records a
        # green run over a file that does not exist.
        code = la.main(["--path", os.path.join(self.dir, "nope-*.log"), "--format", "json"])
        self.assertEqual(code, la.EXIT_NO_INPUT)

    def test_undecodable_bytes_do_not_abort_the_run(self):
        path = os.path.join(self.dir, "app.log")
        with open(path, "wb") as fh:
            fh.write(line(user="before").encode())
            fh.write(b"\xff\xfe corrupt \xff\n")
            fh.write(line(user="after").encode())

        report = la.analyse(la.iter_lines([path], la.Checkpoint(path="")), now=NOW)
        self.assertEqual(report.events_matched, 2)


class CheckpointTests(unittest.TestCase):
    """Bash failure mode: every run rescans the whole file and double-counts."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "app.log")
        self.ckpt = os.path.join(self.dir, "state.json")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_second_run_only_reads_new_lines(self):
        with open(self.log, "w") as fh:
            fh.write(line(user="alice"))

        cp = la.Checkpoint.load(self.ckpt)
        first = la.analyse(la.iter_lines([self.log], cp), now=NOW)
        cp.save()
        self.assertEqual(first.events_matched, 1)

        with open(self.log, "a") as fh:
            fh.write(line(user="bob"))

        cp2 = la.Checkpoint.load(self.ckpt)
        second = la.analyse(la.iter_lines([self.log], cp2), now=NOW)
        cp2.save()
        self.assertEqual(second.events_matched, 1, "alice must not be counted twice")
        self.assertEqual(second.top_users, [("bob", 1)])

    def test_copytruncate_rotation_restarts_from_zero(self):
        with open(self.log, "w") as fh:
            fh.write(line(user="alice") * 10)

        cp = la.Checkpoint.load(self.ckpt)
        list(la.iter_lines([self.log], cp))
        cp.save()

        # logrotate copytruncate: same inode, file is now much smaller.
        with open(self.log, "w") as fh:
            fh.write(line(user="bob"))

        cp2 = la.Checkpoint.load(self.ckpt)
        report = la.analyse(la.iter_lines([self.log], cp2), now=NOW)
        self.assertEqual(report.events_matched, 1, "post-truncation data must not be skipped")

    def test_corrupt_checkpoint_does_not_stop_the_run(self):
        with open(self.ckpt, "w") as fh:
            fh.write("{not json at all")
        with open(self.log, "w") as fh:
            fh.write(line(user="alice"))

        cp = la.Checkpoint.load(self.ckpt)
        report = la.analyse(la.iter_lines([self.log], cp), now=NOW)
        self.assertEqual(report.events_matched, 1)

    def test_checkpoint_write_is_atomic(self):
        cp = la.Checkpoint(path=self.ckpt, offsets={"1:2": 42})
        cp.save()
        self.assertFalse(os.path.exists(self.ckpt + ".tmp"))
        with open(self.ckpt) as fh:
            self.assertEqual(json.load(fh)["offsets"], {"1:2": 42})


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.report = la.analyse([line(user="alice")] * 3 + [line(user="bob")], now=NOW)

    def test_json_output_is_valid_and_versioned(self):
        payload = json.loads(la.render(self.report, "json", "app", "prod"))
        self.assertEqual(payload["schema"], "smartology.failed_logins/v1")
        self.assertEqual(payload["top_users"][0], {"username": "alice", "failures": 3})

    def test_prometheus_output_is_well_formed(self):
        text = la.render(self.report, "prometheus", "app", "prod")
        self.assertIn('failed_logins_total{service="app",env="prod",username="alice"} 3', text)
        self.assertIn("# TYPE failed_logins_total gauge", text)

    def test_emf_output_declares_its_metrics(self):
        payload = json.loads(la.render(self.report, "emf", "app", "prod"))
        names = [m["Name"] for m in payload["_aws"]["CloudWatchMetrics"][0]["Metrics"]]
        self.assertIn("FailedLogins", names)
        self.assertIn("LogFormatDrift", names)

    def test_prometheus_label_values_are_escaped(self):
        report = la.analyse(['WARN Failed login. Username=[a"b]\n'], now=NOW)
        text = la.render(report, "prometheus", "app", "prod")
        self.assertNotIn('username="a"b"', text)


class ExitCodeTests(unittest.TestCase):
    """Exit codes are the contract with cron, systemd and CI. Test them."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "app.log")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _run(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = la.main(["--path", self.log] + list(args))
        return code, buf.getvalue()

    def test_clean_run_exits_zero(self):
        with open(self.log, "w") as fh:
            fh.write(line(user="alice"))
        code, _ = self._run("--format", "json")
        self.assertEqual(code, la.EXIT_OK)

    def test_threshold_breach_exit_code(self):
        with open(self.log, "w") as fh:
            fh.write(line(user="attacker") * 40)
        code, _ = self._run("--format", "json", "--fail-over", "10")
        self.assertEqual(code, la.EXIT_THRESHOLD)

    def test_drift_exit_code(self):
        with open(self.log, "w") as fh:
            fh.write("<html>502</html>\n" * 100)
        code, _ = self._run("--format", "json")
        self.assertEqual(code, la.EXIT_FORMAT_DRIFT)

    def test_drift_can_be_downgraded_explicitly(self):
        with open(self.log, "w") as fh:
            fh.write("<html>502</html>\n" * 100)
        code, _ = self._run("--format", "json", "--allow-drift")
        self.assertEqual(code, la.EXIT_OK)

    def test_bad_window_argument_is_rejected(self):
        with open(self.log, "w") as fh:
            fh.write(line())
        code, _ = self._run("--window", "fifteen-minutes")
        self.assertEqual(code, la.EXIT_ERROR)


class EndToEndTests(unittest.TestCase):
    """Run it the way cron will, as a subprocess, and check the real exit status."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "app.log")
        self.script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log_analyzer.py")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_subprocess_missing_file_is_a_failure(self):
        proc = subprocess.run(
            [sys.executable, self.script, "--path", os.path.join(self.dir, "absent*.log")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, la.EXIT_NO_INPUT)
        self.assertIn("Refusing to report zero", proc.stderr)

    def test_subprocess_happy_path_emits_parseable_json(self):
        with open(self.log, "w") as fh:
            for _ in range(7):
                fh.write(line(user="alice"))
            fh.write(line(user="bob"))

        proc = subprocess.run(
            [sys.executable, self.script, "--path", self.log, "--top", "2", "--format", "json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["top_users"][0]["username"], "alice")
        self.assertEqual(payload["top_users"][0]["failures"], 7)


class PerformanceTests(unittest.TestCase):
    """Not a benchmark — a guard that the implementation stayed streaming."""

    def test_memory_is_bounded_by_cardinality_not_volume(self):
        import tracemalloc

        def run(n_lines, n_users):
            gen = (line(user="u%d" % (i % n_users)) for i in range(n_lines))
            tracemalloc.start()
            la.analyse(gen, now=NOW)
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            return peak

        small = run(2_000, 10)
        large = run(60_000, 10)

        # 30x the lines, same distinct users. Peak memory must not scale with
        # volume. `sort | uniq -c` fails this test by construction.
        self.assertLess(large, small * 3, "memory appears to scale with input size")


if __name__ == "__main__":
    unittest.main(verbosity=2)
