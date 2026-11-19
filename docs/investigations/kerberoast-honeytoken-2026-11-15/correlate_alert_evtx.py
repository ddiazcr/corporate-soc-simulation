#!/usr/bin/env python3
"""
Correlate a Wazuh alert (rule 100212) with the DC01 Security events it came from.

Inputs
  --alert     the Wazuh alert JSON (one alerts.json line, pretty-printed or not)
  --events    DC01-kerberos-logon-window.json from export_dc01_evtx.ps1
              (events parsed by Windows itself: the ground truth for field values)
  --hayabusa  optional Hayabusa timeline in JSONL (dfir-timeline -t jsonl in v4,
              json-timeline -L in v3): which records Hayabusa's rules flagged

Output (Markdown, stdout or --out)
  1. Field-by-field check: alert vs the EVTX record with the same EventRecordID
  2. Timeline of Kerberos/logon events within +/- --window minutes of that record,
     with Hayabusa detections per record when given
  3. Facts the analyst needs before escalating (counted, not inferred)

Exit code: 0 if the record is found and every compared field matches, 1 otherwise.
Standard library only.
"""
import argparse
import json
import sys
from datetime import datetime, timedelta

# Fields compared between the alert (data.win.eventdata, camelCase) and the
# EVTX record (EventData, PascalCase). Compared case-insensitively by name.
CAMPOS = ["TargetUserName", "TargetDomainName", "ServiceName", "ServiceSid", "IpAddress",
          "IpPort", "TicketOptions", "TicketEncryptionType", "Status", "LogonGuid"]

ENC = {"0x17": "RC4", "0x18": "RC4-EXP", "0x11": "AES128", "0x12": "AES256", "0x1": "DES", "0x3": "DES"}


def leer_json(ruta):
    with open(ruta, encoding="utf-8-sig") as f:
        return json.load(f)


def sin_mayus(d):
    return {str(k).lower(): v for k, v in (d or {}).items()}


def hora(texto):
    """ISO-8601 with Z / offset and up to 7 fractional digits -> aware datetime."""
    t = texto.strip().replace("Z", "+00:00")
    if "." in t:
        base, resto = t.split(".", 1)
        frac = "".join(c for c in resto if c.isdigit())
        zona = resto[len(frac):]
        t = f"{base}.{frac[:6].ljust(6, '0')}{zona}"
    return datetime.fromisoformat(t)


def leer_hayabusa(ruta):
    """RecordID -> list of 'Level · RuleTitle'. Key names matched case-insensitively."""
    detecciones = {}
    with open(ruta, encoding="utf-8-sig") as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            try:
                d = sin_mayus(json.loads(linea))
            except json.JSONDecodeError:
                continue
            rid = d.get("recordid")
            if rid in (None, "", "-"):
                continue
            detecciones.setdefault(str(rid), []).append(
                f"{d.get('level', '?')} · {d.get('ruletitle', '?')}")
    return detecciones


def comparar(alerta, registro):
    win = alerta.get("data", {}).get("win", {})
    sysd, ev = win.get("system", {}), sin_mayus(win.get("eventdata"))
    datos = sin_mayus(registro.get("EventData"))
    filas = [("EventRecordID", sysd.get("eventRecordID"), str(registro.get("RecordId"))),
             ("EventID", sysd.get("eventID"), str(registro.get("EventId"))),
             ("Computer", sysd.get("computer"), registro.get("Computer"))]
    t_alerta, t_evtx = sysd.get("systemTime"), registro.get("TimeCreated")
    filas.append(("Event time (UTC, to the second)",
                  hora(t_alerta).strftime("%Y-%m-%dT%H:%M:%SZ") if t_alerta else None,
                  hora(t_evtx).strftime("%Y-%m-%dT%H:%M:%SZ") if t_evtx else None))
    for campo in CAMPOS:
        filas.append((campo, ev.get(campo.lower()), datos.get(campo.lower())))
    return [(n, a, e, a is not None and e is not None and str(a).lower() == str(e).lower())
            for n, a, e in filas]


def resumen(ev):
    d = sin_mayus(ev.get("EventData"))
    cuenta = d.get("targetusername") or d.get("subjectusername") or ""
    ip = (d.get("ipaddress") or "").replace("::ffff:", "")
    enc = d.get("ticketencryptiontype") or ""
    return {"cuenta": cuenta, "servicio": d.get("servicename") or "", "ip": ip,
            "enc": f"{enc} ({ENC[enc.lower()]})" if enc.lower() in ENC else enc,
            "estado": d.get("status") or ""}


def informe(alerta, eventos, hayabusa, ventana_min):
    sysd = alerta.get("data", {}).get("win", {}).get("system", {})
    rid = str(sysd.get("eventRecordID"))
    regla = alerta.get("rule", {})
    out = [f"# Correlation: Wazuh alert {regla.get('id')} ↔ DC01 EventRecordID {rid}", ""]
    out += [f"- Wazuh alert id `{alerta.get('id')}`, agent {alerta.get('agent', {}).get('id')} · "
            f"{alerta.get('agent', {}).get('name')}, rule {regla.get('id')} level {regla.get('level')}",
            f"- EVTX events loaded: {len(eventos)}" +
            (f"; Hayabusa detections on {len(hayabusa)} records" if hayabusa is not None else
             "; Hayabusa timeline not given"), ""]

    registro = next((e for e in eventos if str(e.get("RecordId")) == rid), None)
    if registro is None:
        out += [f"**Record {rid} is not in the EVTX export.** The alert cannot be tied to the "
                "raw log: widen the export window or check whether the log rolled over.", ""]
        return "\n".join(out), False

    filas = comparar(alerta, registro)
    ok = all(f[3] for f in filas)
    out += ["## 1. Alert vs EVTX record", "", "| Field | Wazuh alert | EVTX (Get-WinEvent) | Match |",
            "|---|---|---|---|"]
    out += [f"| {n} | `{a}` | `{e}` | {'✅' if m else '❌'} |" for n, a, e, m in filas]
    out += ["", f"**Result:** {'every compared field matches' if ok else 'MISMATCH — see ❌ rows'}.", ""]

    t0 = hora(registro["TimeCreated"])
    desde, hasta = t0 - timedelta(minutes=ventana_min), t0 + timedelta(minutes=ventana_min)
    cerca = sorted((e for e in eventos if desde <= hora(e["TimeCreated"]) <= hasta),
                   key=lambda e: (hora(e["TimeCreated"]), int(e.get("RecordId", 0))))
    out += [f"## 2. Timeline (±{ventana_min} min, UTC, DC clock)", "",
            "| Time | Record | Event | Account | Service | Client IP | Encryption | Status | Hayabusa |",
            "|---|---|---|---|---|---|---|---|---|"]
    for e in cerca:
        r = resumen(e)
        marca = " **← alert**" if str(e.get("RecordId")) == rid else ""
        hb = "; ".join(hayabusa.get(str(e.get("RecordId")), [])) if hayabusa is not None else "n/a"
        out.append(f"| {hora(e['TimeCreated']).strftime('%H:%M:%S.%f')[:-3]} | {e.get('RecordId')}{marca} | "
                   f"{e.get('EventId')} | {r['cuenta']} | {r['servicio']} | {r['ip']} | {r['enc']} | "
                   f"{r['estado']} | {hb or '—'} |")

    base = resumen(registro)
    tgs_ip = [e for e in cerca if e.get("EventId") == 4769 and resumen(e)["ip"] == base["ip"]]
    servicios = sorted({resumen(e)["servicio"] for e in tgs_ip})
    rc4 = [e for e in tgs_ip if (sin_mayus(e.get("EventData")).get("ticketencryptiontype") or "").lower() == "0x17"]
    tgt = [e for e in cerca if e.get("EventId") == 4768 and resumen(e)["ip"] == base["ip"]
           and hora(e["TimeCreated"]) <= t0]
    fallos = [e for e in cerca if e.get("EventId") in (4771, 4625)
              or (e.get("EventId") in (4768, 4769) and resumen(e)["estado"] not in ("", "0x0"))]
    out += ["", "## 3. Facts for the analyst (counted in the window, not inferred)", "",
            f"- Service tickets (4769) from {base['ip']}: {len(tgs_ip)}, for {len(servicios)} "
            f"service(s): {', '.join(servicios) or '—'}; RC4 among them: {len(rc4)}",
            f"- TGT requests (4768) from {base['ip']} before the alert: {len(tgt)}" +
            (f" (accounts: {', '.join(sorted({resumen(e)['cuenta'] for e in tgt}))})" if tgt else ""),
            f"- Kerberos/logon failures in the window: {len(fallos)}"]
    if hayabusa is not None:
        out.append(f"- Hayabusa detection on the alerted record: "
                   f"{'; '.join(hayabusa.get(rid, [])) or 'none (no Hayabusa rule matched it)'}")
    return "\n".join(out) + "\n", ok


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--alert", required=True)
    p.add_argument("--events", required=True)
    p.add_argument("--hayabusa")
    p.add_argument("--window", type=int, default=10, help="minutes around the alerted record")
    p.add_argument("--out")
    a = p.parse_args(argv)
    eventos = leer_json(a.events)
    if isinstance(eventos, dict):  # ConvertTo-Json of a single event
        eventos = [eventos]
    texto, ok = informe(leer_json(a.alert), eventos,
                        leer_hayabusa(a.hayabusa) if a.hayabusa else None, a.window)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(texto)
    else:
        sys.stdout.write(texto)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
