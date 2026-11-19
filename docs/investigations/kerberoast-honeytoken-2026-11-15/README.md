# Offline investigation — Kerberoasting on the honeytoken (alert 100212, 2026-11-15)

> **Status: prepared, raw log pending.** The Wazuh alert is published evidence;
> the DC01 Security EVTX has not been exported yet. Sections marked ⏳ are filled
> only from the real export — nothing below is inferred from the alert alone
> unless it says so.

## Question

The live run of 2026-11-15 raised rule **100212** (Kerberoasting, T1558.003) on
agent 004 · DC01. Before escalating, an analyst must answer:

1. Does the alert correspond to a real event 4769 in DC01's own Security log, with
   the same values (record, account, service, client address, encryption)?
2. What happened around it: how did the account authenticate, from where, and did
   the same source request other service tickets?
3. Is it malicious, and what still needs checking before handing it to Tier 2?

## Sources

| Source | What it gives | Status |
|---|---|---|
| Wazuh alert JSON | Rule match, agent, decoded 4769 fields | ✅ [`live_kerberoast_alert.json`](../../evidence/live-kerberoast-2026-11-15/live_kerberoast_alert.json) |
| DC01 Security log, time window (`.evtx`) | Raw records, independent of Wazuh | ⏳ export with [`export_dc01_evtx.ps1`](export_dc01_evtx.ps1) |
| Kerberos/logon events of that window (JSON, parsed by Windows) | Ground truth for field values | ⏳ same script |
| Hayabusa timeline (JSONL) | Which records Sigma/Hayabusa rules flag, second opinion on the raw log | ⏳ |
| [`correlate_alert_evtx.py`](correlate_alert_evtx.py) | Field-by-field check, timeline, counted facts | ✅ tested on synthetic data (7 tests) |

## What the alert alone shows

From the published alert (Wazuh's decoding, not yet checked against the raw log):

| Field | Value |
|---|---|
| Event | 4769 *A Kerberos service ticket was requested*, `eventRecordID` 256462, `DC01.lab.local` |
| Event time (DC clock) | 2026-11-15T21:37:36Z — the DC was ~2 h behind; the manager clock was frozen at 2026-11-11, so the alert timestamp is not usable |
| Account | `crojas@LAB.LOCAL` |
| Service | `svc_sql_backup` (honeytoken SPN `MSSQLSvc/db01.lab.local:1433`) |
| Client | `::ffff:192.168.56.103`, port 59238 |
| Ticket encryption / options / status | `0x17` (RC4) / `0x40810010` / `0x0` (issued) |

**Initial assessment (alert only):** high-fidelity indicator. `svc_sql_backup` has
no legitimate use, so any ticket request for it is suspicious by design, and the
RC4 ticket is the format offline cracking needs. Context known from the lab:
this was the authorized test from Kali on 2026-11-15
([evidence](../../evidence/live-kerberoast-2026-11-15/)).

## ⏳ 1. Alert vs raw record

Filled by `correlate_alert_evtx.py` (section 1 of its output) from the real export.

## ⏳ 2. Timeline

Filled from the real export (section 2): every 4768/4769/4770/4771/4624/4625/4634/4672
within ±10 min of record 256462, with Hayabusa's detections per record.

## ⏳ 3. Analyst conclusion

Written after sections 1–2. It must state which of these the raw log confirms:

- the 4769 for `svc_sql_backup` exists with the alerted values;
- a preceding TGT (4768) for the same account from the same address (how the
  account got into Kerberos);
- whether the same address requested tickets for **other** services (one SPN vs a
  roasting sweep) and how many were RC4;
- failures (4771/4625) that would point to password guessing before the request.

## Verify before escalating

| Check | Why | How |
|---|---|---|
| Raw record matches the alert | An alert is a parser's output; the log is the evidence | Section 1: every field ✅ |
| Source host `192.168.56.103` | Asset owner, expected use, whether it is a managed machine | Asset inventory / DHCP; in the lab it is the Kali VM |
| Account `crojas` | Was it used by its owner? Normal workstation, hours, recent password change | 4768/4624 in the window; AD `pwdLastSet`, `lastLogonTimestamp` |
| Breadth | One SPN vs many decides scope | Section 3 of the output: 4769 count and services from the same address |
| Clock | DC ~2 h behind, manager frozen: times from different systems do not line up | Use the event's own `systemTime`; state the offset in the report |
| What logs cannot show | Offline cracking leaves no trace on the DC | Treat the requested ticket as exposed; the honeytoken password is not used anywhere |

Suggested response, **for human approval, not executed**: confirm with the owner of
`crojas`; if unexplained, reset its password, review its recent logons, and
contain the source host. The honeytoken itself needs no reset.

## Reproduce

1. **DC01 (elevated PowerShell)** — copy `export_dc01_evtx.ps1` to DC01 and run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\export_dc01_evtx.ps1
   ```
   It stops with exit 2 if record 256462 rolled out of the log, and with exit 3 if
   the record is outside the window. Output in `C:\IR\kerberoast-2026-11-15\`:
   `DC01-Security-window.evtx`, `SHA256SUMS.txt`, `DC01-kerberos-logon-window.json`.
2. **Copy to the analysis host and verify the hash** (PowerShell):
   ```powershell
   (Get-FileHash -Algorithm SHA256 .\DC01-Security-window.evtx).Hash.ToLower()
   Get-Content .\SHA256SUMS.txt
   ```
3. **Hayabusa** — official release from
   [Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa/releases);
   check the version first, because v4 replaced `csv-timeline`/`json-timeline` with
   `dfir-timeline -t <csv|json|jsonl>` and removed `-L`:
   ```powershell
   .\hayabusa.exe help
   .\hayabusa.exe update-rules
   # v4.x
   .\hayabusa.exe dfir-timeline -f .\DC01-Security-window.evtx -t jsonl -o .\hayabusa-timeline.jsonl
   # v3.x
   .\hayabusa.exe json-timeline -f .\DC01-Security-window.evtx -L -o .\hayabusa-timeline.jsonl
   ```
   If it opens the scan wizard, choose the default rule set; confirm the options
   for UTC output and profile with `.\hayabusa.exe help dfir-timeline`. Record the
   exact version and rule update in the evidence README.
4. **Correlate** (Python 3, standard library):
   ```bash
   python correlate_alert_evtx.py \
     --alert ../../evidence/live-kerberoast-2026-11-15/live_kerberoast_alert.json \
     --events DC01-kerberos-logon-window.json \
     --hayabusa hayabusa-timeline.jsonl --window 10 --out correlation.md
   ```
   Exit 0 means the record was found and every compared field matches.

## Publishing

Lab-only data: `lab.local` accounts, host-only addresses (192.168.56.0/24), lab
domain SIDs. Publish the filtered `.evtx` with its SHA-256, the JSON, the Hayabusa
JSONL and `correlation.md` under `docs/evidence/`; if the `.evtx` is too large for
the repo, publish its hash and the derived files only, and say so.
