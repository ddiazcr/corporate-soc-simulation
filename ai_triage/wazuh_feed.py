"""
Feed real Wazuh alerts into the AI triage pipeline.

The Wazuh manager in this lab has no Internet access (host-only network), so
the model cannot be called from it. Instead, the analyst workstation (which
does have Internet) reads the manager's alerts.json over SSH and triages each
qualifying alert as it arrives. Nothing is pushed from the SIEM to the
Internet, and nothing is ever executed against the domain.

Usage
  Live (streams new alerts as Wazuh writes them; one SSH session, python3 on the manager):
    python wazuh_feed.py --ssh usuario@192.168.56.102
  Replay a copy of alerts.json (or '-' for stdin):
    python wazuh_feed.py --file alerts.json
  Only convert, without calling the model (writes a JSON array):
    python wazuh_feed.py --file alerts.json --convert wazuh_alerts.json

Flags
  --all     triage every alert at level >= MIN_LEVEL, not only Nimbrek rules
  --no-dedup  open a new case for every alert
  --from-end  live mode: ignore the checkpoint and start with new alerts only

Live mode resumes after a stop. The remote reader tags every line with the
file's inode and the byte offset where the line ends; after each alert is
handled (triage AND a row in `decisiones`), that position and the alert id are
recorded in casos_ad.db for this manager (feed_cursor, feed_procesadas). On
start the reader continues from the recorded position, so an alert written
during the stop is read even if its timestamp is older than the last one
handled; an alert already handled is skipped. If the file was rotated or
truncated since (inode changed or file shorter), the current file is replayed
from its start and the reader says so; alerts between the checkpoint and the
rotation stay in the rotated file. --file never reads or writes the checkpoint.

The SSH user needs read access to /var/ossec/logs/alerts/alerts.json
(one-time, on the manager:  sudo usermod -aG wazuh <usuario>  then log in again).

Live mode requires key-based SSH authentication (BatchMode): an automated
reader must not depend on an interactive password prompt. Verify with:
    ssh -o BatchMode=yes usuario@192.168.56.102 "echo ok"
"""

import os
import sys
import json
import base64
import queue
import threading
import subprocess
from datetime import datetime, timezone

import soc_ai_triage as triage

ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"
MAX_RAW = 1500  # cap the raw event text sent to the model
EOF_WAIT_S = 5.0    # bounded wait for ssh's exit status after the stream ends
STOP_WAIT_S = 5.0   # bounded wait after terminate() before kill()
EXIT_STREAM_LOST = 2
EXIT_REMOTE_NO_READ = 3   # remote preflight: alerts.json missing or unreadable
QUEUE_MAX = 1000          # bounded hand-off between the reader thread and main


class StreamCerrado(RuntimeError):
    """The live alert stream ended without the analyst asking for it.

    Raised even when ssh exits with status 0: in live mode the remote
    follower never ends on its own, so any end of stream is a failure.
    """

    def __init__(self, codigo):
        self.codigo = codigo
        if codigo == EXIT_REMOTE_NO_READ:
            msg = (f"El usuario SSH no puede leer {ALERTS_PATH} en el manager "
                   f"(código {codigo}). Solución, en el manager: "
                   f"sudo usermod -aG wazuh <usuario>  y volver a iniciar sesión.")
        else:
            msg = (f"El stream de alertas se cerró inesperadamente "
                   f"(código de salida de ssh: {codigo}). No se están recibiendo alertas.")
        super().__init__(msg)


def _get(d, *path, default=None):
    for p in path:
        if not isinstance(d, dict):
            return default
        d = d.get(p)
    return d if d is not None else default


def convertir(wazuh):
    """Map one Wazuh alert (alerts.json line) to the pipeline's alert format."""
    rule = wazuh.get("rule", {})
    win = _get(wazuh, "data", "win", default={}) or {}
    ev = win.get("eventdata", {}) or {}
    sysd = win.get("system", {}) or {}
    mitre = _get(rule, "mitre", "id", default=[]) or []
    event_id = str(sysd.get("eventID", "")) or None

    # For group-membership events the affected user is the member, not the group
    target = ev.get("targetUserName")
    if event_id in {"4728", "4732", "4756"} and ev.get("memberName"):
        target = ev["memberName"].split(",")[0].replace("CN=", "")

    src_ip = ev.get("ipAddress") or _get(wazuh, "data", "srcip")
    if src_ip:
        src_ip = src_ip.replace("::ffff:", "")

    raw = sysd.get("message") or wazuh.get("full_log") or json.dumps(ev, ensure_ascii=False)
    raw = " ".join(str(raw).split())[:MAX_RAW]

    return {
        "rule_id": str(rule.get("id")),
        "level": int(rule.get("level", 0)),
        "event_id": event_id,
        "mitre_id": mitre[0] if mitre else None,
        "timestamp": wazuh.get("timestamp"),
        "description": rule.get("description"),
        "src_ip": src_ip,
        "dest_ip": _get(wazuh, "agent", "ip") or _get(wazuh, "agent", "name"),
        "target_user": target,
        "subject_user": ev.get("subjectUserName"),
        "service_name": ev.get("serviceName"),
        "object_name": ev.get("objectName"),  # 4662: GUID of the accessed AD object
        "raw_log": raw,
        "_wazuh_id": wazuh.get("id"),
    }


def califica(alerta, todas):
    if alerta["level"] < triage.MIN_LEVEL:
        return False
    return todas or alerta["rule_id"].startswith("1002")


def comando_ssh(destino, cursor=None):
    # -T: no remote TTY. BatchMode: key-based auth only, so a rejected key fails
    #     fast instead of silently waiting on a password prompt.
    # ServerAlive*: detect a dead manager instead of hanging forever.
    return [
        "ssh", "-T",
        "-o", "BatchMode=yes",
        "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
        destino, comando_remoto(cursor=cursor),
    ]


# Remote follower for alerts.json, run with python3 on the manager.
# Why not `tail -F`: the manager runs uutils coreutils (`tail (uutils
# coreutils) 0.8.0`), and its -F printed the initial lines but never the lines
# appended afterwards (verified 2026-11-08: the file grew by 2,782 bytes while
# `timeout 20 tail -n 0 -F alerts.json | wc -c` returned 0). This reader seeks
# to the end, emits complete lines only (a line still being written is held
# until its newline), flushes each one, and reopens the file when it is
# rotated (new inode) or truncated.
SEGUIDOR_PY = r'''# Remote alerts.json follower (runs on the manager under python3).
# Replaces `tail -F`: this Ubuntu ships uutils tail 0.8.0, whose -F did not
# deliver appended lines. Seeks to the end, emits complete lines only, and
# reopens the file when it is rotated (new inode) or truncated.
import os, sys, time, select
path = sys.argv[1]
# Optional cursor (inode, byte offset) from the last handled line: continue
# from there. Without it, start at the end. Every emitted line is prefixed
# with "@<inode>:<offset after the line> " so the client can record it.
cursor = (int(sys.argv[2]), int(sys.argv[3])) if len(sys.argv) > 3 else None
# Exit when the reader side is gone (SSH session closed), even if no alert
# arrives to trigger a broken-pipe error: POLLERR/POLLHUP are always reported.
salida = select.poll()
salida.register(sys.stdout.fileno(), 0)
sys.stderr.write("wazuh_feed: remote reader pid %d\n" % os.getpid())
sys.stderr.flush()
f = open(path, "rb")
ino = os.fstat(f.fileno()).st_ino
if cursor is None:
    f.seek(0, 2)
elif cursor[0] == ino and cursor[1] <= os.fstat(f.fileno()).st_size:
    f.seek(cursor[1])
else:
    sys.stderr.write("wazuh_feed: alerts.json was rotated or truncated since the checkpoint; "
                     "replaying the current file from its start\n")
    sys.stderr.flush()
pend = b""
while True:
    chunk = f.readline()
    if chunk:
        pend += chunk
        if pend.endswith(b"\n"):
            sys.stdout.buffer.write(b"@%d:%d " % (ino, f.tell()) + pend)
            sys.stdout.flush()
            pend = b""
        continue
    time.sleep(0.5)
    if salida.poll(0):
        sys.exit(0)
    try:
        st = os.stat(path)
    except OSError:
        continue
    if st.st_ino != ino or st.st_size < f.tell():
        f.close()
        f = open(path, "rb")
        ino = os.fstat(f.fileno()).st_ino
        pend = b""
'''


def comando_remoto(ruta=None, cursor=None):
    """Remote shell command run by the live session.

    * Preflight: an unreadable file must fail visibly; exit EXIT_REMOTE_NO_READ.
    * The follower travels base64-encoded and is fed to `python3 -` on stdin,
      so the command has no quotes to survive Windows argument quoting.
    * The follower prints its own PID on stderr (`remote reader pid N`), so a
      test can stop exactly this session without touching other SSH sessions.
    """
    ruta = ruta or ALERTS_PATH
    extra = ""
    if cursor is not None:
        ino, pos = cursor
        if not (type(ino) is int and type(pos) is int and ino >= 0 and pos >= 0):
            # It ends up in a remote shell command: two non-negative integers only.
            raise ValueError(f"cursor inválido: {cursor!r}")
        extra = f" {ino} {pos}"
    b64 = base64.b64encode(SEGUIDOR_PY.encode()).decode()
    return (f"test -r {ruta} || {{ echo wazuh_feed: cannot read {ruta} >&2; exit {EXIT_REMOTE_NO_READ}; }}; "
            f"echo {b64} | base64 -d | python3 -u - {ruta}{extra}")


def _detener(proc):
    """Stop ssh and reap it: terminate, bounded wait, then kill."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=STOP_WAIT_S)
        except subprocess.TimeoutExpired:
            proc.kill()
    return proc.wait()


def lineas_ssh(destino, eof_wait=EOF_WAIT_S, cola_max=QUEUE_MAX, cursor=None):
    """Yield alert lines from the manager as they are written.

    Two different endings:
      * voluntary (Ctrl+C, or the consumer closes the generator): ssh is
        stopped and reaped, nothing is reported;
      * unexpected end of stream (EOF): ssh's exit status is collected with a
        bounded wait and StreamCerrado is raised, whatever that status is.

    ssh runs in its own process group so the console's Ctrl+C reaches only
    Python; otherwise ssh would die on its own and a voluntary stop would look
    like a lost connection. The pipe is read in a thread so Ctrl+C is handled
    within a fraction of a second even when no alerts are arriving (a blocking
    pipe read on Windows is not interrupted by Ctrl+C). ssh's stderr is
    inherited, so its own diagnostics stay on stderr.
    """
    cmd = comando_ssh(destino, cursor)
    print(f"Escuchando alertas en vivo: {' '.join(cmd)}  (Ctrl+C para salir)\n")
    grupo = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt"
             else {"start_new_session": True})
    # Binary, unbuffered pipe read line by line: no text-mode read-ahead, so each
    # alert is handed over as soon as its line arrives.
    # stdin=DEVNULL: ssh must never read the analyst's keyboard. Inherited, it
    # competed with the approval prompt for each keystroke and forwarded the
    # ones it won to the manager (2026-11-11 live run: "a" + Enter recorded as
    # skipped on two of three alerts).
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, bufsize=0, **grupo)
    print(f"  ssh local PID: {proc.pid}")
    # Bounded: if triage falls behind (a human answering the approval prompt),
    # the reader blocks instead of buffering without limit, and the backlog
    # waits in the pipe/ssh. `parar` lets a blocked reader give up on a stop.
    cola = queue.Queue(maxsize=cola_max)
    parar = threading.Event()

    def entregar(item):
        while not parar.is_set():
            try:
                cola.put(item, timeout=0.2)
                return True
            except queue.Full:
                continue
        return False

    def lector():
        try:
            for raw in iter(proc.stdout.readline, b""):
                if not entregar(raw):
                    break
        finally:
            proc.stdout.close()
            entregar(None)  # end-of-stream marker (skipped once stopping)

    hilo = threading.Thread(target=lector, name="wazuh-feed-lector", daemon=True)
    hilo.start()

    eof = False
    try:
        while True:
            try:
                raw = cola.get(timeout=0.5)
            except queue.Empty:
                continue
            if raw is None:
                eof = True
                break
            yield raw.decode("utf-8", errors="replace")
    finally:
        if eof:
            try:
                codigo = proc.wait(timeout=eof_wait)
            except subprocess.TimeoutExpired:
                codigo = _detener(proc)
        else:
            parar.set()       # unblock a reader stuck on a full queue
            _detener(proc)    # its pipe closes, so readline() returns
        hilo.join(timeout=STOP_WAIT_S)
    raise StreamCerrado(codigo)  # only reached after an unexpected EOF


# --------------------------------------------------------------------------- #
# Checkpoint (live mode only): per manager, what this feed already handled
# --------------------------------------------------------------------------- #
def init_checkpoint(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS feed_cursor (
        manager TEXT PRIMARY KEY, inode INTEGER, posicion INTEGER, momento TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS feed_procesadas (
        manager TEXT, wazuh_id TEXT, caso_id TEXT, momento TEXT,
        PRIMARY KEY (manager, wazuh_id))""")
    conn.commit()


def manager_de(destino):
    """Checkpoint key: the host part of user@host."""
    return destino.rsplit("@", 1)[-1].lower()


def cursor_guardado(conn, manager):
    fila = conn.execute("SELECT inode, posicion FROM feed_cursor WHERE manager=?", (manager,)).fetchone()
    return (int(fila[0]), int(fila[1])) if fila else None


def guardar_cursor(conn, manager, cursor):
    if cursor is None:
        return
    conn.execute("INSERT OR REPLACE INTO feed_cursor VALUES (?,?,?,?)",
                 (manager, cursor[0], cursor[1], datetime.now(timezone.utc).isoformat()))
    conn.commit()


def ya_procesada(conn, manager, wazuh_id):
    return wazuh_id is not None and conn.execute(
        "SELECT 1 FROM feed_procesadas WHERE manager=? AND wazuh_id=?", (manager, wazuh_id)).fetchone() is not None


def marcar_procesada(conn, manager, alerta, caso_id):
    conn.execute("INSERT OR IGNORE INTO feed_procesadas VALUES (?,?,?,?)",
                 (manager, alerta.get("_wazuh_id"), caso_id, datetime.now(timezone.utc).isoformat()))
    conn.commit()


def separar_cursor(linea):
    """'@<inode>:<offset> {json}' -> ((inode, offset), '{json}'); untagged -> (None, line)."""
    if linea.startswith("@"):
        cabeza, _, resto = linea.partition(" ")
        try:
            ino, pos = cabeza[1:].split(":")
            return (int(ino), int(pos)), resto
        except ValueError:
            pass
    return None, linea


def asegurar_decision(conn, caso_id, entrada=input):
    """Every case reached by the live feed ends with a row in `decisiones`.

    procesar_alerta stores the case before notifying and asking the analyst.
    If the feed stopped in between, the replayed alert is merged into that
    case by dedup (counter only) and nobody is asked; a case without an AI
    verdict is never asked either. Ask now; without a terminal the gate
    records 'pending', linked to the case."""
    if not caso_id or conn.execute("SELECT 1 FROM decisiones WHERE caso_id=?", (caso_id,)).fetchone():
        return
    fila = conn.execute("SELECT analisis_ia, accion_sugerida FROM casos WHERE id=?", (caso_id,)).fetchone()
    if not fila:
        return
    analisis = json.loads(fila[0]) if fila[0] else {"accion_sugerida": fila[1] or "manual_review"}
    print(f"  Caso {caso_id} sin decisión registrada (interrupción anterior o sin análisis de IA): "
          f"se pide ahora.")
    triage.solicitar_aprobacion(conn, caso_id, analisis, entrada=entrada)


def lineas_archivo(ruta):
    f = sys.stdin if ruta == "-" else open(ruta, encoding="utf-8", errors="replace")
    with f:
        for linea in f:
            yield linea


def main():
    argv = sys.argv[1:]
    todas = "--all" in argv
    forzar = "--no-dedup" in argv
    desde_el_final = "--from-end" in argv

    def valor(flag):
        return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else None

    if not (valor("--ssh") or valor("--file")):
        print(__doc__)
        sys.exit(1)

    salida = valor("--convert")
    convertidas, vistos = [], set()
    codigo_salida = 0
    conn = None if salida else triage.init_db()
    if conn:
        print(f"Modo={triage.MODE} | nivel mínimo {triage.MIN_LEVEL} | "
              f"{'todas las reglas' if todas else 'solo reglas Nimbrek (1002xx)'}\n")

    # Checkpoint only for live mode with triage, keyed by manager.
    manager = manager_de(valor("--ssh")) if (valor("--ssh") and conn) else None
    if manager:
        init_checkpoint(conn)
    if valor("--ssh"):
        cursor = None if (desde_el_final or not manager) else cursor_guardado(conn, manager)
        print(f"Retomando {manager} desde la posición {cursor[1]} (inode {cursor[0]})." if cursor
              else "Sin punto de retoma: se escuchan solo las alertas nuevas.")
        fuente = lineas_ssh(valor("--ssh"), cursor=cursor)
    else:
        fuente = lineas_archivo(valor("--file"))
    atendida = None   # position of the last line fully handled

    try:
        for linea in fuente:
            pos, linea = separar_cursor(linea.strip())
            if not linea.startswith("{"):
                atendida = pos or atendida
                continue
            try:
                alerta = convertir(json.loads(linea))
            except (json.JSONDecodeError, ValueError, TypeError):
                atendida = pos or atendida
                continue
            if not califica(alerta, todas) or alerta["_wazuh_id"] in vistos:
                if not salida and alerta["rule_id"].startswith("1002"):
                    # Visible trace so a live run is never silent about what it saw
                    print(f"  · recibida regla {alerta['rule_id']} nivel {alerta['level']} (no se triagea)")
                atendida = pos or atendida
                continue
            vistos.add(alerta["_wazuh_id"])
            if salida:
                convertidas.append(alerta)
                continue
            if manager and ya_procesada(conn, manager, alerta["_wazuh_id"]):
                print(f"  · alerta {alerta['_wazuh_id']} ya atendida antes, se omite")
                atendida = pos or atendida
                continue
            print(f"\n>>> Wazuh {alerta['timestamp']} regla {alerta['rule_id']} "
                  f"(nivel {alerta['level']}) {alerta['src_ip']} -> {alerta['dest_ip']}")
            res = triage.procesar_alerta(conn, alerta, forzar_nuevo=forzar)
            caso_id = res[0] if isinstance(res, tuple) else res
            if manager:
                asegurar_decision(conn, caso_id)
                # Recorded only now: a stop before this point replays the alert.
                marcar_procesada(conn, manager, alerta, caso_id)
                atendida = pos or atendida
                guardar_cursor(conn, manager, atendida)
    except KeyboardInterrupt:
        print("\nDetenido por el analista.")
    except StreamCerrado as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        if e.codigo != EXIT_REMOTE_NO_READ:
            print(f"  Revisar que la VM de Wazuh esté arriba y que la llave SSH funcione:\n"
                  f"    ssh -o BatchMode=yes {valor('--ssh')} \"echo ok\"", file=sys.stderr)
        codigo_salida = EXIT_STREAM_LOST
    finally:
        # Voluntary stop: closing the generator stops and reaps ssh.
        if hasattr(fuente, "close"):
            fuente.close()
        if manager:
            # Lines skipped since the last alert are not read again.
            guardar_cursor(conn, manager, atendida)

    if salida:
        with open(salida, "w", encoding="utf-8") as f:
            json.dump(convertidas, f, ensure_ascii=False, indent=2)
        print(f"{len(convertidas)} alertas convertidas -> {salida}")
    if conn:
        conn.close()
    return codigo_salida


if __name__ == "__main__":
    sys.exit(main())
