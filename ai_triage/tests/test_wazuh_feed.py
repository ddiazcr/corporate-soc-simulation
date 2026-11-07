"""
Tests for the live SSH feed in wazuh_feed.py.

A stand-in `ssh` executable (bash) is placed first on PATH so every scenario is
deterministic: alert timing, remote exit status (including 0), a stream that
closes while ssh keeps running, and a voluntary stop. POSIX only (the stand-in
is a shell script); the equivalent checks on the Windows analyst host are
manual and listed in ai_triage/README.md ("Live feed checks").

Run from the ai_triage folder:
    python -m unittest discover -s tests -v
"""

import os
import sys
import time
import signal
import tempfile
import textwrap
import unittest
import subprocess

AI_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, AI_DIR)

import wazuh_feed  # noqa: E402

ALERT_100212 = (
    '{"timestamp":"2026-11-07T23:24:05Z","id":"t1","rule":{"id":"100212","level":12,'
    '"description":"test","mitre":{"id":["T1558.003"]}},"agent":{"name":"DC01"},'
    '"data":{"win":{"system":{"eventID":"4769"},"eventdata":{"serviceName":"svc_sql_backup"}}}}'
)
ALERT_LEVEL8 = '{"id":"t2","rule":{"id":"100210","level":8}}'

FAKE_SSH = textwrap.dedent(r"""
    #!/bin/bash
    # Stand-in for ssh. Behaviour selected by $FAKE_SSH_MODE.
    # 'exec' keeps it a single process, like the real ssh client.
    [ -n "$FAKE_SSH_PIDFILE" ] && echo $$ > "$FAKE_SSH_PIDFILE"
    case "$FAKE_SSH_MODE" in
      one_then_hang)   echo "$FAKE_LINE"; exec sleep 30 ;;
      one_then_exit0)  echo "$FAKE_LINE"; exit 0 ;;
      one_then_exit255) echo "$FAKE_LINE"; echo "ssh: connection lost" >&2; exit 255 ;;
      close_stdout_hang) echo "$FAKE_LINE"; exec 1>&-; exec sleep 30 ;;
      hang)            exec sleep 30 ;;
    esac
""").lstrip()


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A reaped-or-zombie check: a zombie still answers kill(0) until reaped.
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split()[2] != "Z"
    except FileNotFoundError:
        return False


class LiveFeedTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bin = os.path.join(self.tmp.name, "bin")
        os.mkdir(self.bin)
        ssh = os.path.join(self.bin, "ssh")
        with open(ssh, "w") as f:
            f.write(FAKE_SSH)
        os.chmod(ssh, 0o755)
        self.pidfile = os.path.join(self.tmp.name, "ssh.pid")
        self._env = dict(os.environ)
        os.environ["PATH"] = self.bin + os.pathsep + os.environ["PATH"]
        os.environ["FAKE_SSH_PIDFILE"] = self.pidfile
        os.environ["FAKE_LINE"] = ALERT_100212

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        self.tmp.cleanup()

    def _ssh_pid(self, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(self.pidfile):
                with open(self.pidfile) as f:
                    txt = f.read().strip()
                if txt:
                    return int(txt)
            time.sleep(0.05)
        self.fail("fake ssh did not start")

    # 1 ------------------------------------------------------------------ #
    def test_alert_is_delivered_without_waiting_for_the_next_one(self):
        os.environ["FAKE_SSH_MODE"] = "one_then_hang"
        gen = wazuh_feed.lineas_ssh("lab@manager")
        t0 = time.time()
        first = next(gen)
        elapsed = time.time() - t0
        gen.close()
        self.assertIn('"100212"', first)
        self.assertLess(elapsed, 2.0, "first alert was held back")

    # 2 ------------------------------------------------------------------ #
    def test_remote_eof_with_exit_code_0_is_a_failure(self):
        os.environ["FAKE_SSH_MODE"] = "one_then_exit0"
        gen = wazuh_feed.lineas_ssh("lab@manager")
        self.assertIn('"100212"', next(gen))
        with self.assertRaises(wazuh_feed.StreamCerrado) as ctx:
            next(gen)
        self.assertEqual(ctx.exception.codigo, 0)

    def test_remote_eof_with_exit_code_255_is_a_failure(self):
        os.environ["FAKE_SSH_MODE"] = "one_then_exit255"
        gen = wazuh_feed.lineas_ssh("lab@manager")
        next(gen)
        with self.assertRaises(wazuh_feed.StreamCerrado) as ctx:
            next(gen)
        self.assertEqual(ctx.exception.codigo, 255)

    # 3 ------------------------------------------------------------------ #
    def test_eof_while_ssh_keeps_running_uses_a_bounded_wait(self):
        os.environ["FAKE_SSH_MODE"] = "close_stdout_hang"
        gen = wazuh_feed.lineas_ssh("lab@manager", eof_wait=1.0)
        next(gen)
        pid = self._ssh_pid()
        t0 = time.time()
        with self.assertRaises(wazuh_feed.StreamCerrado):
            next(gen)
        self.assertLess(time.time() - t0, 1.0 + wazuh_feed.STOP_WAIT_S + 1.0)
        self.assertFalse(_alive(pid), "ssh left running after EOF")

    # 4 ------------------------------------------------------------------ #
    def test_voluntary_close_stops_ssh_and_reports_nothing(self):
        os.environ["FAKE_SSH_MODE"] = "one_then_hang"
        gen = wazuh_feed.lineas_ssh("lab@manager")
        next(gen)
        pid = self._ssh_pid()
        gen.close()  # must not raise StreamCerrado
        self.assertFalse(_alive(pid), "ssh left running after voluntary stop")

    # 5 ------------------------------------------------------------------ #
    def _run_main(self, mode, line=ALERT_LEVEL8):
        env = dict(os.environ, FAKE_SSH_MODE=mode, FAKE_LINE=line, AI_MODE="SIMULADO",
                   PYTHONUNBUFFERED="1")
        code = ("import sys; sys.path.insert(0, %r); sys.argv=['wazuh_feed.py','--ssh','lab@manager'];"
                "import wazuh_feed; sys.exit(wazuh_feed.main())" % AI_DIR)
        return subprocess.Popen([sys.executable, "-c", code], cwd=self.tmp.name, env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, start_new_session=True)

    def test_ssh_mode_exits_nonzero_when_stream_closes_with_code_0(self):
        p = self._run_main("one_then_exit0")
        out, err = p.communicate(timeout=20)
        self.assertEqual(p.returncode, wazuh_feed.EXIT_STREAM_LOST)
        self.assertIn("[ERROR]", err)
        self.assertIn("código de salida de ssh: 0", err)
        self.assertNotIn("Detenido por el analista", out)

    def test_ctrl_c_releases_ssh_without_reporting_a_lost_connection(self):
        p = self._run_main("hang")
        pid = self._ssh_pid()
        time.sleep(0.5)
        # What a console Ctrl+C does: SIGINT to the foreground process group.
        # ssh runs in its own group, so only Python receives it.
        os.killpg(p.pid, signal.SIGINT)
        out, err = p.communicate(timeout=20)
        self.assertEqual(p.returncode, 0)
        self.assertIn("Detenido por el analista", out)
        self.assertNotIn("[ERROR]", err)
        self.assertFalse(_alive(pid), "ssh left running after Ctrl+C")

    # 6 ------------------------------------------------------------------ #
    def test_command_is_key_only_and_line_buffered(self):
        cmd = wazuh_feed.comando_ssh("lab@manager")
        self.assertIn("-T", cmd)
        self.assertIn("BatchMode=yes", cmd)
        self.assertTrue(cmd[-1].startswith("stdbuf -oL tail -n 0 -F "))


if __name__ == "__main__":
    unittest.main()
