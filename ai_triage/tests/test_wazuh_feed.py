"""
Tests for the live SSH feed in wazuh_feed.py.

Two groups:

* SshCommandTests — platform-independent (any OS, no ssh needed).
* StandInSshTests — REQUIRE LINUX + BASH. A stand-in `ssh` (bash script) is put
  first on PATH so every scenario is deterministic: alert timing, remote exit
  status (including 0), a stream that closes while ssh keeps running, a full
  hand-off queue during cancellation, and the real remote command (preflight +
  python3 follower) executed locally against a temp file. Skipped elsewhere.

These results come from the stand-in, not from OpenSSH. The checks on the
Windows analyst host (real OpenSSH, real manager) are separate and listed in
ai_triage/README.md ("Live feed checks").

Run from the ai_triage folder:
    python -m unittest discover -s tests -v
"""

import os
import sys
import time
import signal
import shutil
import threading
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
      flood_then_hang) for i in $(seq 1 5000); do echo "$FAKE_LINE"; done; exec sleep 30 ;;
      no_read)         echo "wazuh_feed: cannot read alerts.json" >&2; exit 3 ;;
      exec_remote)     # run the real remote command locally; on TERM, stop the whole
                       # group, like sshd closing the session ends the remote side
                       trap 'kill 0' TERM; bash -c "${@: -1}" & wait $!; exit $? ;;
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


LINUX_BASH = sys.platform.startswith("linux") and shutil.which("bash") is not None


class SshCommandTests(unittest.TestCase):
    """Platform-independent: inspects the command line only."""

    def test_command_is_key_only_and_uses_the_python_follower(self):
        cmd = wazuh_feed.comando_ssh("lab@manager")
        self.assertIn("-T", cmd)
        self.assertIn("BatchMode=yes", cmd)
        self.assertIn("base64 -d | python3 -u - ", cmd[-1])
        self.assertNotIn("tail", cmd[-1], "uutils tail -F does not follow; must not be used")

    def test_remote_command_has_read_preflight_and_reports_its_pid(self):
        remoto = wazuh_feed.comando_remoto("/x/alerts.json")
        self.assertTrue(remoto.startswith("test -r /x/alerts.json || "))
        self.assertIn(f"exit {wazuh_feed.EXIT_REMOTE_NO_READ}", remoto)
        import base64, re
        b64 = re.search(r"echo (\S+) \| base64 -d", remoto).group(1)
        seguidor = base64.b64decode(b64).decode()
        self.assertEqual(seguidor, wazuh_feed.SEGUIDOR_PY)
        self.assertIn("remote reader pid", seguidor)
        self.assertNotIn('"', remoto, "double quotes would break Windows argument quoting")


@unittest.skipUnless(LINUX_BASH, "requires Linux + bash (stand-in ssh is a bash script)")
class StandInSshTests(unittest.TestCase):

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
    def _run_main(self, mode, line=ALERT_LEVEL8, alerts_path=None):
        env = dict(os.environ, FAKE_SSH_MODE=mode, FAKE_LINE=line, AI_MODE="SIMULADO",
                   PYTHONUNBUFFERED="1")
        patch = f"wazuh_feed.ALERTS_PATH = {alerts_path!r}; " if alerts_path else ""
        code = ("import sys; sys.path.insert(0, %r); sys.argv=['wazuh_feed.py','--ssh','lab@manager'];"
                "import wazuh_feed; %ssys.exit(wazuh_feed.main())" % (AI_DIR, patch))
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
    def test_cancel_with_a_full_queue_does_not_hang(self):
        os.environ["FAKE_SSH_MODE"] = "flood_then_hang"
        gen = wazuh_feed.lineas_ssh("lab@manager", cola_max=5)
        next(gen)
        pid = self._ssh_pid()
        time.sleep(0.5)  # let the reader fill the 5-slot queue and block on put()
        t0 = time.time()
        gen.close()
        self.assertLess(time.time() - t0, wazuh_feed.STOP_WAIT_S + 1.0)
        self.assertFalse(_alive(pid), "ssh left running")
        time.sleep(0.5)
        lectores = [t for t in threading.enumerate() if t.name == "wazuh-feed-lector"]
        self.assertEqual(lectores, [], "reader thread still blocked on a full queue")

    # 7 ------------------------------------------------------------------ #
    def test_unreadable_alerts_file_fails_visibly_with_exit_2(self):
        # Root ignores file modes, so "unreadable" is exercised with a missing
        # path: `test -r` is false in both cases.
        missing = os.path.join(self.tmp.name, "no-such-alerts.json")
        p = self._run_main("exec_remote", alerts_path=missing)
        out, err = p.communicate(timeout=20)
        self.assertEqual(p.returncode, wazuh_feed.EXIT_STREAM_LOST)
        self.assertIn("cannot read", err)          # remote preflight, ssh stderr
        self.assertIn("no puede leer", err)        # feed's own diagnosis
        self.assertIn("usermod -aG wazuh", err)

    def _seguir(self, alerts, accion, timeout=6.0):
        """Run the real remote command (via the stand-in) against `alerts`,
        call `accion()` in a thread, and return the first delivered line.

        The deadline applies to the WAIT for the line: next(gen) runs in a
        thread; if no line arrives in time, the stand-in's process group is
        killed (ending the stream) and the test fails, so a follower that
        stays silent with the session open cannot hang the suite."""
        os.environ["FAKE_SSH_MODE"] = "exec_remote"
        old = wazuh_feed.ALERTS_PATH
        wazuh_feed.ALERTS_PATH = alerts
        resultado = {}
        try:
            gen = wazuh_feed.lineas_ssh("lab@manager")

            def esperar_linea():
                try:
                    linea = next(gen)
                    while wazuh_feed.separar_cursor(linea.strip())[1] == "#start":
                        linea = next(gen)          # the follower's start mark, not an alert
                    resultado["linea"] = linea
                except BaseException as e:   # StreamCerrado once the group is killed
                    resultado["error"] = e

            lector = threading.Thread(target=esperar_linea, daemon=True)
            lector.start()
            pid = self._ssh_pid()
            threading.Thread(target=accion, daemon=True).start()
            lector.join(timeout)
            if lector.is_alive():
                os.killpg(pid, signal.SIGKILL)   # end the stream, release next()
                lector.join(wazuh_feed.EOF_WAIT_S + wazuh_feed.STOP_WAIT_S)
                self.fail(f"no line delivered within {timeout}s")
            gen.close()
        finally:
            wazuh_feed.ALERTS_PATH = old
        if "error" in resultado:
            raise resultado["error"]
        return resultado["linea"]

    def test_follower_holds_a_partial_line_until_its_newline(self):
        alerts = os.path.join(self.tmp.name, "alerts.json")
        open(alerts, "w").close()
        mitad = len(ALERT_100212) // 2

        def escribir_en_dos_partes():
            time.sleep(0.8)
            with open(alerts, "a") as f:
                f.write(ALERT_100212[:mitad]); f.flush()
                time.sleep(1.2)          # follower polls in between
                f.write(ALERT_100212[mitad:] + "\n")
        line = self._seguir(alerts, escribir_en_dos_partes)
        pos, cuerpo = wazuh_feed.separar_cursor(line.strip())
        self.assertEqual(cuerpo, ALERT_100212)   # one complete line, not two halves
        self.assertEqual(pos, (os.stat(alerts).st_ino, os.path.getsize(alerts)))   # cursor = end of that line

    def test_follower_reopens_a_rotated_file(self):
        alerts = os.path.join(self.tmp.name, "alerts.json")
        open(alerts, "w").close()

        def rotar_y_escribir():
            time.sleep(0.8)
            os.rename(alerts, alerts + ".1")             # rotation: new file, new inode
            with open(alerts, "w") as f:
                f.write(ALERT_100212 + "\n")
        line = self._seguir(alerts, rotar_y_escribir)
        self.assertIn('"100212"', line)

    def test_follower_exits_when_the_session_closes_with_no_alerts(self):
        """Real remote command, no alerts arriving. Closing the reader side (what
        sshd does when the SSH session ends) must end the remote follower, not
        leave it polling forever on the manager."""
        alerts = os.path.join(self.tmp.name, "alerts.json")
        open(alerts, "w").close()
        p = subprocess.Popen(["bash", "-c", wazuh_feed.comando_remoto(alerts)],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        time.sleep(1.0)          # follower is up and idle
        p.stdout.close()         # session gone
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait()
            self.fail("remote follower kept running after the session closed")

    def test_real_remote_command_streams_a_line_appended_after_start(self):
        alerts = os.path.join(self.tmp.name, "alerts.json")
        open(alerts, "w").close()

        def append_later():
            time.sleep(0.7)
            with open(alerts, "a") as f:
                f.write(ALERT_100212 + "\n")
        line = self._seguir(alerts, append_later, timeout=3.0)
        self.assertIn('"100212"', line)

    def test_silent_follower_cannot_hang_the_suite(self):
        """The helper's deadline itself: nothing is ever written, so it must
        fail on time and leave no process behind."""
        alerts = os.path.join(self.tmp.name, "alerts.json")
        open(alerts, "w").close()
        t0 = time.time()
        with self.assertRaises(AssertionError):
            self._seguir(alerts, lambda: None, timeout=1.5)
        self.assertLess(time.time() - t0, 1.5 + wazuh_feed.EOF_WAIT_S + wazuh_feed.STOP_WAIT_S + 1)
        self.assertFalse(_alive(self._ssh_pid()), "stand-in left running after the deadline")


if __name__ == "__main__":
    unittest.main()
