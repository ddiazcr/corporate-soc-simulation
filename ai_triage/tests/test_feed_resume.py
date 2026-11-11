"""
Tests for resuming the live feed after a stop: byte cursor in the remote
follower, per-manager checkpoint, no double triage, --file isolation, and a
decision row for every case the feed reaches.

Run from the ai_triage folder:
    python -m unittest discover -s tests -v
"""
import json
import os
import selectors
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import soc_ai_triage as triage  # noqa: E402
import wazuh_feed  # noqa: E402


def alerta(ts, wid, regla="100212", nivel=12, ip="::1"):
    return json.dumps({
        "timestamp": ts, "id": wid,
        "rule": {"id": regla, "level": nivel, "description": "test", "mitre": {"id": ["T1558.003"]}},
        "agent": {"name": "DC01", "ip": "192.168.56.10"},
        "data": {"win": {"system": {"eventID": "4769"},
                         "eventdata": {"serviceName": "svc_sql_backup", "ipAddress": ip,
                                       "ticketEncryptionType": "0x17"}}},
    }, separators=(",", ":"))


T = ["2026-11-11T16:%02d:00.000+0000" % m for m in (10, 20, 30, 40, 50)]


class CursorFormatTests(unittest.TestCase):

    def test_cursor_is_passed_as_two_integers(self):
        self.assertTrue(wazuh_feed.comando_remoto("/x/alerts.json", (920032, 1772296))
                        .endswith("/x/alerts.json 920032 1772296"))
        self.assertTrue(wazuh_feed.comando_remoto("/x/alerts.json").endswith("/x/alerts.json"))

    def test_anything_but_two_non_negative_integers_is_refused(self):
        for malo in (("1", "2"), (1, "2; id"), (-1, 5), (1.5, 2), (True, 3)):
            with self.subTest(cursor=malo):
                with self.assertRaises(ValueError):
                    wazuh_feed.comando_remoto("/x/alerts.json", malo)

    def test_line_prefix_parsing(self):
        self.assertEqual(wazuh_feed.separar_cursor('@12:345 {"a":1}'), ((12, 345), '{"a":1}'))
        self.assertEqual(wazuh_feed.separar_cursor('{"a":1}'), (None, '{"a":1}'))
        self.assertEqual(wazuh_feed.separar_cursor("@x:y {}"), (None, "@x:y {}"))


@unittest.skipUnless(os.name == "posix", "the follower runs on the Linux manager")
class FollowerCursorTests(unittest.TestCase):

    def _seguir(self, ruta, *cursor):
        p = subprocess.Popen([sys.executable, "-u", "-", ruta, *map(str, cursor)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.stdin.write(wazuh_feed.SEGUIDOR_PY.encode())
        p.stdin.close()
        return p

    def _leer(self, p, n, timeout=5):
        """Raw reads: a buffered readline() could swallow several lines while
        the selector reports the pipe once."""
        sel = selectors.DefaultSelector()
        sel.register(p.stdout, selectors.EVENT_READ)
        buf, out, fin = b"", [], time.time() + timeout
        while len(out) < n and time.time() < fin:
            if sel.select(0.2):
                buf += os.read(p.stdout.fileno(), 65536)
                *lineas, buf = buf.split(b"\n")
                for x in lineas:
                    if x:
                        pos, cuerpo = wazuh_feed.separar_cursor(x.decode())
                        if cuerpo == "#start":
                            self.inicio = pos
                            continue
                        out.append((pos, json.loads(cuerpo)["id"]))
        return out

    def _escribir(self, ruta, *items):
        with open(ruta, "a") as f:
            for ts, wid in items:
                f.write(alerta(ts, wid) + "\n")

    def test_alert_written_during_the_stop_is_read_even_with_an_older_timestamp(self):
        """ChatGPT's case: last handled alert at 16:30; while the feed is
        stopped Wazuh appends one stamped 16:20. A timestamp filter drops it;
        the byte cursor reads it."""
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, "alerts.json")
            self._escribir(ruta, (T[0], "a0"), (T[2], "a1"))
            cursor = (os.stat(ruta).st_ino, os.path.getsize(ruta))     # a1 handled, then stop
            self._escribir(ruta, (T[1], "tarde"), (T[3], "a2"))         # written while stopped
            p = self._seguir(ruta, *cursor)
            try:
                ids = [i for _, i in self._leer(p, 2)]
            finally:
                p.kill(); p.wait()
            self.assertEqual(ids, ["tarde", "a2"])

    def test_every_line_carries_its_inode_and_end_offset(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, "alerts.json")
            open(ruta, "w").close()
            p = self._seguir(ruta)                     # no cursor: start at the end
            try:
                time.sleep(0.8)
                self._escribir(ruta, (T[0], "a0"))
                (pos, wid), = self._leer(p, 1)
            finally:
                p.kill(); p.wait()
            self.assertEqual((pos, wid), ((os.stat(ruta).st_ino, os.path.getsize(ruta)), "a0"))
            self.assertEqual(self.inicio, (os.stat(ruta).st_ino, 0))     # start mark: before any alert

    def test_rotated_file_is_replayed_from_its_start_and_reported(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, "alerts.json")
            self._escribir(ruta, (T[0], "viejo"))
            cursor = (os.stat(ruta).st_ino, os.path.getsize(ruta))
            os.rename(ruta, ruta + ".1")                               # daily rotation
            self._escribir(ruta, (T[1], "nuevo0"), (T[2], "nuevo1"))
            p = self._seguir(ruta, *cursor)
            try:
                ids = [i for _, i in self._leer(p, 2)]
            finally:
                p.kill(); p.wait()
                err = p.stderr.read().decode()
            self.assertEqual(ids, ["nuevo0", "nuevo1"])
            self.assertIn("rotated or truncated", err)


class MainCheckpointTests(unittest.TestCase):
    """main() with a stubbed SSH/file source and, unless said otherwise, a stubbed triage."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.orig = (wazuh_feed.lineas_ssh, wazuh_feed.lineas_archivo, triage.procesar_alerta,
                     triage.solicitar_aprobacion, sys.argv)
        self.triageadas, self.cursores = [], []

        def fuente(destino, cursor=None, **kw):
            self.cursores.append(cursor)
            yield from self.lineas
        wazuh_feed.lineas_ssh = fuente
        wazuh_feed.lineas_archivo = lambda ruta: iter(self.lineas)

        def triage_falso(conn, a, **kw):
            self.triageadas.append(a["_wazuh_id"])
            caso = f"caso-{a['_wazuh_id']}-{len(self.triageadas)}"
            conn.execute("INSERT INTO casos (id, analisis_ia, accion_sugerida, estado) VALUES (?,?,?,?)",
                         (caso, json.dumps({"accion_sugerida": "escalate_tier2"}), "escalate_tier2", "analizado"))
            conn.execute("INSERT INTO decisiones (caso_id, accion_sugerida, decision, analista, momento) "
                         "VALUES (?,?,?,?,?)", (caso, "escalate_tier2", "approved", "t", "now"))
            conn.commit()
            return caso, {}
        triage.procesar_alerta = triage_falso

    def tearDown(self):
        (wazuh_feed.lineas_ssh, wazuh_feed.lineas_archivo, triage.procesar_alerta,
         triage.solicitar_aprobacion, sys.argv) = self.orig
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def _main(self, *args):
        sys.argv = ["wazuh_feed.py", *args]
        return wazuh_feed.main()

    def _db(self):
        return sqlite3.connect("casos_ad.db")

    def test_resumes_from_the_last_handled_alert_and_skips_it_on_replay(self):
        self.lineas = ["@7:100 " + alerta(T[2], "A")]
        self._main("--ssh", "lab@192.168.56.102")
        self.lineas = ["@7:100 " + alerta(T[2], "A"), "@7:200 " + alerta(T[1], "tarde")]
        self._main("--ssh", "lab@192.168.56.102")
        self.assertEqual(self.cursores, [None, (7, 100)])
        self.assertEqual(self.triageadas, ["A", "tarde"])             # A once; the late one too
        with self._db() as c:
            self.assertEqual(c.execute("SELECT caso_id FROM feed_procesadas WHERE wazuh_id='tarde'").fetchone()[0],
                             "caso-tarde-2")

    def test_skipped_lines_advance_the_cursor_on_exit(self):
        self.lineas = ["@7:100 " + alerta(T[0], "A"), "@7:150 " + alerta(T[1], "bajo", regla="60106", nivel=3)]
        self._main("--ssh", "lab@192.168.56.102")
        self.lineas = []
        self._main("--ssh", "lab@192.168.56.102")
        self.assertEqual(self.cursores[-1], (7, 150))

    def test_file_mode_between_two_live_sessions_leaves_the_checkpoint_alone(self):
        self.lineas = ["@7:100 " + alerta(T[1], "A")]
        self._main("--ssh", "lab@192.168.56.102")
        self.lineas = [alerta(T[4], "F")]                               # replay of a copy
        self._main("--file", "copia.json")
        self.lineas = []
        self._main("--ssh", "lab@192.168.56.102")
        self.assertEqual(self.cursores[-1], (7, 100))
        with self._db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM feed_procesadas WHERE wazuh_id='F'").fetchone()[0], 0)

    def test_checkpoint_is_per_manager(self):
        self.lineas = ["@7:100 " + alerta(T[1], "A")]
        self._main("--ssh", "lab@192.168.56.102")
        self.lineas = ["@9:50 " + alerta(T[1], "A")]                   # same alert id, other manager
        self._main("--ssh", "lab@10.0.0.5")
        self.assertEqual(self.cursores, [None, None])
        self.assertEqual(self.triageadas, ["A", "A"])

    def test_from_end_ignores_the_checkpoint(self):
        self.lineas = ["@7:100 " + alerta(T[1], "A")]
        self._main("--ssh", "lab@192.168.56.102")
        self.lineas = []
        self._main("--ssh", "lab@192.168.56.102", "--from-end")
        self.assertEqual(self.cursores[-1], None)

    def test_alert_is_not_recorded_if_triage_stops_midway(self):
        def falla(conn, a, **kw):
            raise RuntimeError("stop mid-triage")
        triage.procesar_alerta = falla
        self.lineas = ["@7:100 " + alerta(T[1], "A")]
        with self.assertRaises(RuntimeError):
            self._main("--ssh", "lab@192.168.56.102")
        self.lineas = []
        self._main("--ssh", "lab@192.168.56.102")
        self.assertIsNone(self.cursores[-1])                           # cursor did not pass A
        with self._db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM feed_procesadas").fetchone()[0], 0)


class InterruptedReviewTests(unittest.TestCase):
    """Real procesar_alerta (simulated model). The feed stops after the case is
    committed and before the analyst decides; on restart the replayed alert
    is merged into that case by dedup, and the decision must still be taken."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.orig = (wazuh_feed.lineas_ssh, triage.notificar, triage.MODE, triage.solicitar_aprobacion, sys.argv)
        triage.MODE = "SIMULADO"
        wazuh_feed.lineas_ssh = lambda destino, cursor=None, **kw: iter(self.lineas)

    def tearDown(self):
        (wazuh_feed.lineas_ssh, triage.notificar, triage.MODE, triage.solicitar_aprobacion, sys.argv) = self.orig
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def test_stop_after_the_case_commit_ends_with_a_decision_linked_to_that_case(self):
        self.lineas = ["@7:100 " + alerta(T[1], "A")]

        def corte(*a, **kw):
            raise KeyboardInterrupt        # analyst/host stops the feed right after the case commit
        triage.notificar = corte
        sys.argv = ["wazuh_feed.py", "--ssh", "lab@192.168.56.102"]
        wazuh_feed.main()
        with sqlite3.connect("casos_ad.db") as c:
            (caso,), = c.execute("SELECT id FROM casos").fetchall()
            self.assertEqual(c.execute("SELECT COUNT(*) FROM decisiones").fetchone()[0], 0)

        triage.notificar = self.orig[1]
        pedidas = []
        orig_sol = self.orig[3]

        def solicitar(conn, caso_id, analisis, entrada=input, analista="analista"):
            pedidas.append(caso_id)
            return orig_sol(conn, caso_id, analisis, entrada=lambda *_: "a", analista=analista)
        triage.solicitar_aprobacion = solicitar
        wazuh_feed.main()                  # restart: same alert replayed
        with sqlite3.connect("casos_ad.db") as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM casos").fetchone()[0], 1)          # merged, not duplicated
            self.assertEqual(c.execute("SELECT caso_id, decision FROM decisiones").fetchall(), [(caso, "approved")])
            self.assertEqual(c.execute("SELECT caso_id FROM feed_procesadas WHERE wazuh_id='A'").fetchone()[0], caso)
        self.assertEqual(pedidas, [caso])

    def test_without_a_terminal_the_missing_decision_is_recorded_pending(self):
        self.lineas = ["@7:100 " + alerta(T[1], "B")]
        triage.notificar = lambda *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt())
        sys.argv = ["wazuh_feed.py", "--ssh", "lab@192.168.56.102"]
        wazuh_feed.main()
        triage.notificar = self.orig[1]
        wazuh_feed.main()                  # stdin is not a TTY under unittest -> 'pending'
        with sqlite3.connect("casos_ad.db") as c:
            (caso,), = c.execute("SELECT id FROM casos").fetchall()
            self.assertEqual(c.execute("SELECT caso_id, decision FROM decisiones").fetchall(), [(caso, "pending")])

    def test_no_dedup_restart_resumes_the_same_case_instead_of_opening_another(self):
        """With --no-dedup (or an expired dedup window) a replayed alert would
        open a second case; the alert -> case link written at the first save
        makes the restart resume the review on the original case."""
        self.lineas = ["@7:100 " + alerta(T[1], "C")]
        triage.notificar = lambda *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt())
        sys.argv = ["wazuh_feed.py", "--ssh", "lab@192.168.56.102", "--no-dedup"]
        wazuh_feed.main()
        triage.notificar = self.orig[1]
        orig_sol = self.orig[3]
        triage.solicitar_aprobacion = lambda conn, caso_id, analisis, entrada=input, analista="analista": \
            orig_sol(conn, caso_id, analisis, entrada=lambda *_: "r", analista=analista)
        wazuh_feed.main()
        with sqlite3.connect("casos_ad.db") as c:
            (caso,), = c.execute("SELECT id FROM casos").fetchall()                      # still one case
            self.assertEqual(c.execute("SELECT caso_id, decision FROM decisiones").fetchall(), [(caso, "rejected")])
            self.assertEqual(c.execute("SELECT caso_id, estado FROM feed_procesadas WHERE wazuh_id='C'").fetchone(),
                             (caso, "atendida"))


@unittest.skipUnless(os.name == "posix", "runs the real follower through bash")
class FirstStartRealFollowerTests(unittest.TestCase):
    """First start (no checkpoint): the real follower starts at the end of the
    file; the first alert's review is interrupted after the case commit. The
    start mark was recorded before it, so the restart reads it again and the
    review ends on the same case."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.ruta = os.path.join(self.tmp.name, "alerts.json")
        with open(self.ruta, "w") as f:
            f.write(alerta(T[0], "vieja") + "\n")          # before the first start: not ours
        self.orig = (wazuh_feed.comando_ssh, triage.notificar, triage.MODE, triage.solicitar_aprobacion, sys.argv)
        triage.MODE = "SIMULADO"
        wazuh_feed.comando_ssh = lambda destino, cursor=None: ["bash", "-c", wazuh_feed.comando_remoto(self.ruta, cursor)]
        sys.argv = ["wazuh_feed.py", "--ssh", "lab@192.168.56.102"]

    def tearDown(self):
        (wazuh_feed.comando_ssh, triage.notificar, triage.MODE, triage.solicitar_aprobacion, sys.argv) = self.orig
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def _parar_cuando(self, condicion, timeout=15):
        import signal
        import threading

        def vigilar():
            fin = time.time() + timeout
            while time.time() < fin and not condicion():
                time.sleep(0.2)
            os.kill(os.getpid(), signal.SIGINT)              # the analyst's Ctrl+C
        threading.Thread(target=vigilar, daemon=True).start()

    def _db(self, sql):
        try:
            with sqlite3.connect("casos_ad.db") as c:
                return c.execute(sql).fetchall()
        except sqlite3.Error:
            return []

    def test_first_alert_survives_a_hard_kill_after_the_case_commit(self):
        """The first run is killed with SIGKILL (no finally, no clean exit)
        right after the first alert's case is committed."""
        import signal
        bandera = os.path.join(self.tmp.name, "caso_guardado")
        aqui = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        guion = (
            "import os, sys, time\n"
            f"sys.path.insert(0, {aqui!r})\n"
            "import soc_ai_triage as triage, wazuh_feed\n"
            "triage.MODE = 'SIMULADO'\n"
            f"wazuh_feed.comando_ssh = lambda d, cursor=None: ['bash', '-c', wazuh_feed.comando_remoto({self.ruta!r}, cursor)]\n"
            f"def colgar(*a, **k):\n    open({bandera!r}, 'w').close()\n    time.sleep(60)\n"
            "triage.notificar = colgar\n"
            "sys.argv = ['wazuh_feed.py', '--ssh', 'lab@192.168.56.102']\n"
            "wazuh_feed.main()\n")
        p = subprocess.Popen([sys.executable, "-c", guion], cwd=self.tmp.name,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(1.5)                                     # follower started at the end
            with open(self.ruta, "a") as f:
                f.write(alerta(T[2], "primera") + "\n")
            fin = time.time() + 15
            while time.time() < fin and not os.path.exists(bandera):
                time.sleep(0.1)
            self.assertTrue(os.path.exists(bandera), "the case was never committed")
        finally:
            os.kill(p.pid, signal.SIGKILL)                      # hard stop: no finally runs
            p.wait()
        (caso,), = self._db("SELECT id FROM casos")
        self.assertEqual(self._db("SELECT COUNT(*) FROM decisiones"), [(0,)])

        orig_sol = self.orig[3]
        triage.solicitar_aprobacion = lambda conn, caso_id, analisis, entrada=input, analista="analista": \
            orig_sol(conn, caso_id, analisis, entrada=lambda *_: "a", analista=analista)
        self._parar_cuando(lambda: self._db("SELECT 1 FROM feed_procesadas WHERE estado='atendida'"))
        wazuh_feed.main()                                       # restart with the real follower
        self.assertEqual(self._db("SELECT id FROM casos"), [(caso,)])
        self.assertEqual(self._db("SELECT caso_id, decision FROM decisiones"), [(caso, "approved")])
        self.assertEqual(self._db("SELECT wazuh_id, caso_id, estado FROM feed_procesadas"),
                         [("primera", caso, "atendida")])     # 'vieja' was before the first start

if __name__ == "__main__":
    unittest.main()
