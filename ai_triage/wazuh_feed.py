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
"""

import sys
import json
import subprocess

import soc_ai_triage as triage

ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"
MAX_RAW = 1500  # cap the raw event text sent to the model


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


def lineas_ssh(destino):
    cmd = ["ssh", destino, f"tail -n 0 -F {ALERTS_PATH}"]
    print(f"Escuchando alertas en vivo: {' '.join(cmd)}  (Ctrl+C para salir)\n")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    try:
        for linea in proc.stdout:
            yield linea
    finally:
        proc.terminate()


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

    if salida:
        with open(salida, "w", encoding="utf-8") as f:
            json.dump(convertidas, f, ensure_ascii=False, indent=2)
        print(f"{len(convertidas)} alertas convertidas -> {salida}")
    if conn:
        conn.close()


if __name__ == "__main__":
    main()
