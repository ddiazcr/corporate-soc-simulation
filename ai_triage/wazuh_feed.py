"""
Feed real Wazuh alerts into the AI triage pipeline.

The Wazuh manager in this lab has no Internet access (host-only network), so
the model cannot be called from it. Instead, the analyst workstation (which
does have Internet) reads the manager's alerts.json over SSH and triages each
qualifying alert as it arrives. Nothing is pushed from the SIEM to the
Internet, and nothing is ever executed against the domain.

Usage
  Live (streams new alerts as Wazuh writes them; one SSH session):
    python wazuh_feed.py --ssh usuario@192.168.56.102
  Replay a copy of alerts.json (or '-' for stdin):
    python wazuh_feed.py --file alerts.json
  Only convert, without calling the model (writes a JSON array):
    python wazuh_feed.py --file alerts.json --convert wazuh_alerts.json

Flags
  --all     triage every alert at level >= MIN_LEVEL, not only Nimbrek rules
  --no-dedup  open a new case for every alert

The SSH user needs read access to /var/ossec/logs/alerts/alerts.json
(one-time, on the manager:  sudo usermod -aG wazuh <usuario>  then log in again).

Live mode requires key-based SSH authentication (BatchMode): an automated
reader must not depend on an interactive password prompt. Verify with:
    ssh -o BatchMode=yes usuario@192.168.56.102 "echo ok"
"""

import os
import sys
import json
import queue
import threading
import subprocess

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
    `tail -F` never ends on its own, so any end of stream is a failure.
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
        "raw_log": raw,
        "_wazuh_id": wazuh.get("id"),
    }


def califica(alerta, todas):
    if alerta["level"] < triage.MIN_LEVEL:
        return False
    return todas or alerta["rule_id"].startswith("1002")


def comando_ssh(destino):
    # -T: no remote TTY. BatchMode: key-based auth only, so a rejected key fails
    #     fast instead of silently waiting on a password prompt.
    # ServerAlive*: detect a dead manager instead of hanging forever.
    # stdbuf -oL: force the remote tail to flush line by line when its stdout is
    #     not a terminal (otherwise alerts can sit in a block buffer).
    return [
        "ssh", "-T",
        "-o", "BatchMode=yes",
        "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
        destino, comando_remoto(),
    ]


def comando_remoto(ruta=None):
    """Remote shell command run by the live session.

    * Preflight: `tail -F` on an unreadable file does not exit, it retries
      quietly; check readability first and exit with EXIT_REMOTE_NO_READ.
    * Print the remote PID on stderr. `exec` keeps the same PID through stdbuf
      into tail, so this is the PID of *this* session's tail: a test can stop
      exactly this session without touching other SSH sessions.
    No double quotes, so the string survives Windows argument quoting.
    """
    ruta = ruta or ALERTS_PATH
    return (f"test -r {ruta} || {{ echo wazuh_feed: cannot read {ruta} >&2; exit {EXIT_REMOTE_NO_READ}; }}; "
            f"echo wazuh_feed: remote tail pid $$ >&2; "
            f"exec stdbuf -oL tail -n 0 -F {ruta}")


def _detener(proc):
    """Stop ssh and reap it: terminate, bounded wait, then kill."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=STOP_WAIT_S)
        except subprocess.TimeoutExpired:
            proc.kill()
    return proc.wait()


def lineas_ssh(destino, eof_wait=EOF_WAIT_S, cola_max=QUEUE_MAX):
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
    cmd = comando_ssh(destino)
    print(f"Escuchando alertas en vivo: {' '.join(cmd)}  (Ctrl+C para salir)\n")
    grupo = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt"
             else {"start_new_session": True})
    # Binary, unbuffered pipe read line by line: no text-mode read-ahead, so each
    # alert is handed over as soon as its line arrives.
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=0, **grupo)
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


def lineas_archivo(ruta):
    f = sys.stdin if ruta == "-" else open(ruta, encoding="utf-8", errors="replace")
    with f:
        for linea in f:
            yield linea


def main():
    argv = sys.argv[1:]
    todas = "--all" in argv
    forzar = "--no-dedup" in argv

    def valor(flag):
        return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else None

    if valor("--ssh"):
        fuente = lineas_ssh(valor("--ssh"))
    elif valor("--file"):
        fuente = lineas_archivo(valor("--file"))
    else:
        print(__doc__)
        sys.exit(1)

    salida = valor("--convert")
    convertidas, vistos = [], set()
    codigo_salida = 0
    conn = None if salida else triage.init_db()
    if conn:
        print(f"Modo={triage.MODE} | nivel mínimo {triage.MIN_LEVEL} | "
              f"{'todas las reglas' if todas else 'solo reglas Nimbrek (1002xx)'}\n")

    try:
        for linea in fuente:
            linea = linea.strip()
            if not linea.startswith("{"):
                continue
            try:
                alerta = convertir(json.loads(linea))
            except (json.JSONDecodeError, ValueError, TypeError):
                continue
            if not califica(alerta, todas) or alerta["_wazuh_id"] in vistos:
                if not salida and alerta["rule_id"].startswith("1002"):
                    # Visible trace so a live run is never silent about what it saw
                    print(f"  · recibida regla {alerta['rule_id']} nivel {alerta['level']} (no se triagea)")
                continue
            vistos.add(alerta["_wazuh_id"])
            if salida:
                convertidas.append(alerta)
                continue
            print(f"\n>>> Wazuh {alerta['timestamp']} regla {alerta['rule_id']} "
                  f"(nivel {alerta['level']}) {alerta['src_ip']} -> {alerta['dest_ip']}")
            triage.procesar_alerta(conn, alerta, forzar_nuevo=forzar)
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

    if salida:
        with open(salida, "w", encoding="utf-8") as f:
            json.dump(convertidas, f, ensure_ascii=False, indent=2)
        print(f"{len(convertidas)} alertas convertidas -> {salida}")
    if conn:
        conn.close()
    return codigo_salida


if __name__ == "__main__":
    sys.exit(main())
