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
import re
import sys
from datetime import datetime, timedelta

# Fields compared between the alert (data.win.eventdata, camelCase) and the
# EVTX record (EventData, PascalCase). Compared case-insensitively by name.
CAMPOS = ["TargetUserName", "TargetDomainName", "ServiceName", "ServiceSid", "IpAddress",
          "IpPort", "TicketOptions", "TicketEncryptionType", "Status", "LogonGuid"]

ENC = {"0x17": "RC4", "0x18": "RC4-EXP", "0x11": "AES128", "0x12": "AES256", "0x1": "DES", "0x3": "DES"}
# Common codes only; anything else is printed raw.
NT_SUB = {"0xc000006a": "wrong password", "0xc0000064": "no such user", "0xc0000234": "locked out",
          "0xc0000072": "disabled", "0xc000006f": "outside logon hours", "0xc0000071": "password expired"}
KRB = {"0x6": "unknown principal", "0x12": "revoked/disabled", "0x18": "pre-auth failed (bad password)",
       "0x25": "clock skew (KRB_AP_ERR_SKEW)", "0x17": "password expired"}


def leer_json(ruta):
    with open(ruta, encoding="utf-8-sig") as f:
        return json.load(f)


def sin_mayus(d):
    return {str(k).lower(): v for k, v in (d or {}).items()}


_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$", re.I)


def hora(texto):
    """ISO-8601 with Z or an offset and up to 7 fractional digits -> aware
    datetime. The offset is kept (it is parsed apart from the fraction), and a
    timestamp without a zone is refused rather than mixed with UTC ones."""
    m = _ISO.match(texto.strip())
    if not m:
        raise ValueError(f"not an ISO-8601 timestamp: {texto!r}")
    base, frac, zona = m.groups()
    if not zona:
        raise ValueError(f"timestamp without a time zone: {texto!r}")
    zona = "+00:00" if zona.upper() == "Z" else (zona if ":" in zona else f"{zona[:3]}:{zona[3:]}")
    return datetime.fromisoformat(f"{base}{'.' + frac[:6].ljust(6, '0') if frac else ''}{zona}")


def leer_hayabusa(ruta):
    """Hayabusa JSONL -> (RecordID -> ['Level · RuleTitle'], list of rows).
    Key names matched case-insensitively; rows without a RecordID (correlation
    rules) are kept in the list but not indexed."""
    detecciones, filas = {}, []
    with open(ruta, encoding="utf-8-sig") as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            try:
                d = sin_mayus(json.loads(linea))
            except json.JSONDecodeError:
                continue
            filas.append(d)
            rid = d.get("recordid")
            if rid in (None, "", "-"):
                continue
            detecciones.setdefault(str(rid), []).append(
                f"{d.get('level', '?')} · {d.get('ruletitle', '?')}")
    return detecciones, filas


def cuenta_hayabusa(d):
    det = sin_mayus(d.get("details"))
    sujeto, objetivo = det.get("subjectusername"), det.get("targetusername")
    if sujeto and objetivo and sujeto.lower() != objetivo.lower():
        return f"{sujeto} → {objetivo}"           # e.g. 4724: who reset whom
    for k in ("tgtuser", "user", "targetusername", "subjectusername"):
        if det.get(k):
            return det[k]
    return ""


CAMPOS_CUENTA_HB = ("tgtuser", "user", "targetusername", "subjectusername")
CAMPOS_IP_HB = ("srcip", "ipaddress", "sourceaddress")
CAMPOS_LID_HB = ("lid", "subjectlogonid", "targetlogonid")


def ip_normal(valor):
    return str(valor or "").strip().lower().replace("::ffff:", "")


def relacionado_hb(d, cuenta, ip, sesiones):
    """A Hayabusa row is tied to the case only by whole, normalized values in
    identified fields: an account field equal to the alerted account, a
    client-address field equal to the alerted client, or a LogonId of a
    related event on the same computer. No substring matching
    (`crojas_backup` is not `crojas`; 192.168.56.10 is not 192.168.56.103)."""
    det = sin_mayus(d.get("details"))
    if any(base_cuenta(det.get(k)) == cuenta for k in CAMPOS_CUENTA_HB if det.get(k)):
        return True
    if ip and any(ip_normal(det.get(k)) == ip for k in CAMPOS_IP_HB if det.get(k)):
        return True
    equipo = str(d.get("computer") or "").lower()
    return any((equipo, str(det.get(k)).lower()) in sesiones for k in CAMPOS_LID_HB if det.get(k))


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


def base_cuenta(nombre):
    """'crojas@LAB.LOCAL' / 'LAB\\crojas' / 'crojas' -> 'crojas'."""
    n = (nombre or "").split("@")[0]
    return n.split("\\")[-1].lower()


def detalle(ev):
    d = sin_mayus(ev.get("EventData"))
    eid = ev.get("EventId")
    if eid in (4624, 4625):
        partes = [f"type {d.get('logontype')}", d.get("authenticationpackagename") or ""]
        if d.get("workstationname") in ("-", "", None):
            partes.append("no workstation name")
        sub = (d.get("substatus") or "").lower()
        if eid == 4625 and sub:
            partes.append(f"{sub} {NT_SUB.get(sub, '')}".strip())
        return ", ".join(p for p in partes if p)
    if eid in (4768, 4771, 4769):
        st = (d.get("status") or "").lower()
        partes = [f"{st} {KRB.get(st, '')}".strip()] if st not in ("", "0x0") else []
        if d.get("preauthtype") not in (None, ""):
            partes.append(f"pre-auth {d.get('preauthtype')}")
        return ", ".join(partes)
    return ""


def resumen(ev):
    d = sin_mayus(ev.get("EventData"))
    cuenta = d.get("targetusername") or d.get("subjectusername") or ""
    ip = (d.get("ipaddress") or "").replace("::ffff:", "")
    enc = d.get("ticketencryptiontype") or ""
    return {"cuenta": cuenta, "servicio": d.get("servicename") or "", "ip": ip,
            "enc": f"{enc} ({ENC[enc.lower()]})" if enc.lower() in ENC else enc,
            "estado": d.get("status") or "", "detalle": detalle(ev)}


def informe(alerta, eventos, hayabusa, ventana_min, todo=False):
    hb_filas = []
    if isinstance(hayabusa, tuple):
        hayabusa, hb_filas = hayabusa
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
    base = resumen(registro)
    cuenta = base_cuenta(base["cuenta"])
    ligados = [e for e in cerca if resumen(e)["ip"] == base["ip"] or base_cuenta(resumen(e)["cuenta"]) == cuenta]
    filas_tl = cerca if todo else ligados
    # Hayabusa detections on records the native export does not hold (e.g.
    # 4662, 4724): added when tied to the account, the client or a logon
    # session (LogonId) of a related event.
    nativos = {str(e.get("RecordId")) for e in eventos}
    sesiones = {(str(e.get("Computer") or "").lower(), (sin_mayus(e.get("EventData")).get("targetlogonid") or "").lower())
                for e in ligados}
    sesiones = {s_ for s_ in sesiones if s_[1] not in ("", "0x0")}
    solo_hb = []
    for d in hb_filas:
        rid_hb, ts = str(d.get("recordid", "")), d.get("timestamp")
        if not ts or rid_hb in ("", "-", "None") or rid_hb in nativos:
            continue
        if not (desde <= hora(ts) <= hasta):
            continue
        if todo or relacionado_hb(d, cuenta, ip_normal(base["ip"]), sesiones):
            solo_hb.append(d)
    out += [f"## 2. Timeline (±{ventana_min} min, UTC, DC clock)", "",
            (f"All {len(cerca)} Kerberos/logon events in the window." if todo else
             f"Events from client {base['ip']} or for account `{cuenta}`: {len(ligados)} of {len(cerca)} "
             f"in the window; the other {len(cerca) - len(ligados)} (machine account, local service "
             f"logons) are omitted — `--all` lists them.") +
            (f" Plus {len({str(d.get('recordid')) for d in solo_hb})} record(s) only Hayabusa holds, tied by "
             f"account, client or logon session." if solo_hb else ""), "",
            "| Time | Record | Event | Account | Service | Client IP | Encryption | Detail | Hayabusa |",
            "|---|---|---|---|---|---|---|---|---|"]
    filas_md = []
    for e in filas_tl:
        r = resumen(e)
        marca = " **← alert**" if str(e.get("RecordId")) == rid else ""
        hb = "; ".join(hayabusa.get(str(e.get("RecordId")), [])) if hayabusa is not None else "n/a"
        d = sin_mayus(e.get("EventData"))
        lid = d.get("targetlogonid")
        det = ", ".join(x for x in (r["detalle"], f"logon {lid}" if lid and e.get("EventId") in (4624, 4634) else "") if x)
        filas_md.append((hora(e["TimeCreated"]), int(e.get("RecordId", 0)),
                         f"| {hora(e['TimeCreated']).strftime('%H:%M:%S.%f')[:-3]} | {e.get('RecordId')}{marca} | "
                         f"{e.get('EventId')} | {r['cuenta']} | {r['servicio']} | {r['ip']} | {r['enc']} | "
                         f"{det} | {hb or '—'} |"))
    vistos = set()
    for d in solo_hb:
        clave = str(d.get("recordid"))
        titulos = "; ".join(hayabusa.get(clave, [])) if hayabusa else d.get("ruletitle", "")
        if clave in vistos:
            continue
        vistos.add(clave)
        det = sin_mayus(d.get("details"))
        lid = det.get("lid") or det.get("subjectlogonid")
        filas_md.append((hora(d["timestamp"]), int(clave),
                         f"| {hora(d['timestamp']).strftime('%H:%M:%S.%f')[:-3]} | {clave} | {d.get('eventid')} | "
                         f"{cuenta_hayabusa(d)} |  |  |  | Hayabusa only (not in the native export)"
                         f"{f', logon {lid}' if lid else ''} | {titulos} |"))
    out += [f for _, _, f in sorted(filas_md)]

    tgs_ip = [e for e in cerca if e.get("EventId") == 4769 and resumen(e)["ip"] == base["ip"]]
    servicios = sorted({resumen(e)["servicio"] for e in tgs_ip})
    rc4 = [e for e in tgs_ip if (sin_mayus(e.get("EventData")).get("ticketencryptiontype") or "").lower() == "0x17"]
    tgt = [e for e in cerca if e.get("EventId") == 4768 and resumen(e)["ip"] == base["ip"]
           and hora(e["TimeCreated"]) <= t0]
    fallos = [e for e in cerca if e.get("EventId") in (4771, 4625)
              or (e.get("EventId") in (4768, 4769) and resumen(e)["estado"] not in ("", "0x0"))]
    fallos_ip = [e for e in fallos if resumen(e)["ip"] == base["ip"]]
    ntlm_ip = [e for e in cerca if e.get("EventId") == 4624 and resumen(e)["ip"] == base["ip"]
               and (sin_mayus(e.get("EventData")).get("authenticationpackagename") or "").upper() == "NTLM"]
    out += ["", "## 3. Facts for the analyst (counted in the window, not inferred)", "",
            f"- Service tickets (4769) from {base['ip']}: {len(tgs_ip)}, for {len(servicios)} "
            f"service(s): {', '.join(servicios) or '—'}; RC4 among them: {len(rc4)}",
            f"- TGT requests (4768) from {base['ip']} before the alert: {len(tgt)}" +
            (f" (accounts: {', '.join(sorted({resumen(e)['cuenta'] for e in tgt}))})" if tgt else ""),
            f"- Kerberos/logon failures in the window: {len(fallos)}; from {base['ip']}: {len(fallos_ip)}" +
            (" — " + "; ".join(f"{resumen(e)['cuenta']} {e.get('EventId')} {resumen(e)['detalle']}"
                               for e in fallos_ip) if fallos_ip else ""),
            f"- Successful NTLM network logons (4624) from {base['ip']}: {len(ntlm_ip)}" +
            (f" (accounts: {', '.join(sorted({resumen(e)['cuenta'] for e in ntlm_ip}))})" if ntlm_ip else "")]
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
    p.add_argument("--all", action="store_true", help="list every event in the window, not only the related ones")
    p.add_argument("--out")
    a = p.parse_args(argv)
    eventos = leer_json(a.events)
    if isinstance(eventos, dict):  # ConvertTo-Json of a single event
        eventos = [eventos]
    texto, ok = informe(leer_json(a.alert), eventos,
                        leer_hayabusa(a.hayabusa) if a.hayabusa else None, a.window, a.all)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(texto)
    else:
        sys.stdout.write(texto)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
