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


if __name__ == "__main__":
    unittest.main()
