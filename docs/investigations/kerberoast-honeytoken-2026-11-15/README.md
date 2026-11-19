# Offline investigation — Kerberoasting on the honeytoken (alert 100212, 2026-11-15)

> **Status: analysed.** Raw DC01 Security log exported and hashed on the DC
> (2026-11-18), Hayabusa 4.4.0 timeline, field-by-field correlation with the
> Wazuh alert. One item needs operator confirmation before the case can be
> closed in the lab: the password reset of `crojas` (see *Verify before
> escalating*).

## Question

The live run of 2026-11-15 raised rule **100212** (Kerberoasting, T1558.003) on
agent 004 · DC01. Before escalating, an analyst must answer:

1. Does the alert correspond to a real event 4769 in DC01's own Security log, with
   the same values?
2. What happened around it: how did the account authenticate, from where, and did
   the same source do anything else?
3. Is it malicious, and what still needs checking before handing it to Tier 2?

## Sources

| Source | What it gives | Integrity |
|---|---|---|
| Wazuh alert JSON | Rule match, decoded 4769 | [published](../../evidence/live-kerberoast-2026-11-15/live_kerberoast_alert.json) |
| `DC01-Security-window.evtx` (38.9 MB, 46,480 events, 2026-11-15 19:00–23:59Z) | Raw records, independent of Wazuh | SHA-256 `3b837a93…387e0` computed on DC01, re-checked on the analysis host and in the analysis workspace; kept off the repo for size, hash published |
| `DC01-kerberos-logon-window.json` (583 events) | 4768/4769/4770/4771/4624/4625/4634/4672 parsed by `Get-WinEvent` | [published](../../evidence/offline-kerberoast-2026-11-15/) |
| `hayabusa-timeline.jsonl` (92 detections, 13 unique) | Hayabusa 4.4.0, bundled rules, `dfir-timeline -t jsonl -w -O` | [published](../../evidence/offline-kerberoast-2026-11-15/) |
| [`correlation.md`](../../evidence/offline-kerberoast-2026-11-15/correlation.md) | Output of [`correlate_alert_evtx.py`](correlate_alert_evtx.py) | regenerated from the files above |

Chain of custody: export script copied to DC01 and hash-checked against the repo
blob (`fd4d7fcd…8ef4`); EVTX hashed on DC01 before leaving it; same hash after
copy. Hayabusa ZIP hash matched GitHub's published digest (`ec267006…bf339`).

## 1. Alert vs raw record

All **14 compared fields match** between the Wazuh alert and EventRecordID
256462 in the raw log: record, event 4769, computer, time, account
`crojas@LAB.LOCAL`, service `svc_sql_backup` and its SID, client
`::ffff:192.168.56.103` port 59238, ticket options `0x40810010`, encryption
`0x17` (RC4), status `0x0`, logon GUID. The alert is not a parser artefact.

## 2. Timeline

Times are DC01's clock (UTC). Events from the client 192.168.56.103 or for
`crojas`: 11 of 159 Kerberos/logon events in ±10 min, plus 3 records only
Hayabusa holds (4724, 4662), tied by account or logon session.

| Time | Event | What it shows |
|---|---|---|
| 21:29:00 | 4625 `Administrator` | NTLM network logon from .103, **wrong password** (`0xc000006a`), no workstation name |
| 21:29:30, 21:29:41 | 4625 `crojas` ×2 | Same, for `crojas` |
| 21:30:31 | **4724** `Administrator → crojas` | **Password of `crojas` reset by `Administrator`** (logon session `0x9f14e`, opened before the export window: its origin is not in this export) — Hayabusa *Password Reset By Admin* |
| 21:31:04.559 | 4624 `crojas` | NTLM network logon from .103 succeeds (session `0x37072c`) |
| 21:31:04.620 | 4662 `crojas` | Directory object read in that session — Hayabusa *Potential AD User Enumeration* |
| 21:31:04.650, .960 | 4771 ×2 | Kerberos pre-auth fails: **clock skew** (`0x25`) |
| 21:37:36.252 | 4624 `crojas` | NTLM network logon from .103 (session `0x39e0f5`) |
| 21:37:36.259 | 4662 `crojas` | Directory read in that session — *Potential AD User Enumeration* |
| 21:37:36.305 | 4768 `crojas` | TGT issued, **RC4** (`0x17`) |
| 21:37:36.327 | **4769 → alert** | Service ticket for `svc_sql_backup`, **RC4** — Hayabusa *Possible Kerberoasting (RC4)* and *Kerberoasting Activity – Initial Query* (medium) |

## 3. Analyst conclusion

**True positive: Kerberoasting attempt against the honeytoken (T1558.003) from
192.168.56.103, preceded by password guessing (T1110) and directory
enumeration (T1087.002), using the account `crojas`.**

What the raw log confirms:

- **The ticket.** A real 4769 for the honeytoken SPN, RC4, issued (`0x0`), to
  `crojas` from .103. The honeytoken has no legitimate use, so the request alone
  is high-fidelity.
- **Breadth.** One service ticket from .103 in the window, for one service: a
  targeted request, not a sweep of every SPN. Two independent detections agree
  (Wazuh 100212, Hayabusa).
- **How the account got in.** Wrong-password NTLM attempts from .103 against
  `Administrator` and `crojas`, then a password reset of `crojas` by
  `Administrator`, then a successful NTLM logon from .103 a few seconds later.
- **Tooling pattern.** In each session from .103: NTLM logon → directory read →
  TGT → TGS within 75 ms, no workstation name, RC4 TGT (DC01's own TGTs in the
  same export are AES256 `0x12`). Consistent with an Impacket-style
  `GetUserSPNs` run; this is an inference from the pattern, not something the log
  states.
- **Not seen.** Offline cracking of the ticket leaves no trace on the DC; the
  ticket must be treated as exposed (the honeytoken's password is not used
  anywhere, so exposure costs nothing).

## Verify before escalating

| Check | Status | Why it matters |
|---|---|---|
| Raw record matches the alert | ✅ 14/14 | The alert is evidence-backed |
| **Password reset of `crojas` at 21:30:31 by `Administrator`** (session `0x9f14e`) | ⏳ **Operator confirmation** | If it was not an authorised change, the `Administrator` session is compromised and severity rises: escalate immediately. The session's own logon (4624/4672 for `0x9f14e`) predates 19:00Z: re-export from an earlier start to see where it came from |
| Host 192.168.56.103 | Lab inventory: Kali VM | In production: asset owner, managed or not (no workstation name in any logon) |
| Account `crojas` | Used from .103 only after the reset | Contact the owner; recent logons elsewhere; `pwdLastSet` |
| Clocks | DC01 was ~2 h behind on 2026-11-15; the 4771 `0x25` errors are that skew | Use the event's own time; state the offset when comparing with other systems |

**Suggested response (for human approval; nothing executed):** confirm the reset
with its author; if unexplained, treat `Administrator` as compromised (review
session `0x9f14e`, reset its password, check other DCs); reset `crojas` and
review its logons; contain 192.168.56.103. The honeytoken needs no change.

**Lab context.** This was the authorised Kerberoasting test from Kali on
2026-11-15 ([live detection](../../evidence/live-kerberoast-2026-11-15/)). The
reset is expected to be the operator setting a known password for the test
account; that is what the open check above records until confirmed.

## Reproduce

1. **DC01 (elevated PowerShell)** — copy [`export_dc01_evtx.ps1`](export_dc01_evtx.ps1)
   (e.g. through `\\192.168.56.10\C$`) and check its SHA-256 against the repo; run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\export_dc01_evtx.ps1
   ```
   Exit 2: record 256462 rolled out of the log (circular, 256 MB; it held records
   1–258,396 on 2026-11-18). Exit 3: record outside the window.
2. **Copy and verify** — `Get-FileHash` on the copy must equal `SHA256SUMS.txt`.
3. **Hayabusa** (v4.x; v4 merged `csv-timeline`/`json-timeline` into `dfir-timeline`):
   ```powershell
   .\hayabusa-4.4.0-win-x64.exe dfir-timeline -f .\DC01-Security-window.evtx -t jsonl -o .\hayabusa-timeline.jsonl -w -O
   ```
   `-w` no wizard (all events and alerts), `-O` ISO-8601 UTC. Bundled rules; do not
   run `update-rules` if the result must match this one.
4. **Correlate** (Python 3, standard library):
   ```bash
   python correlate_alert_evtx.py \
     --alert ../../evidence/live-kerberoast-2026-11-15/live_kerberoast_alert.json \
     --events DC01-kerberos-logon-window.json \
     --hayabusa hayabusa-timeline.jsonl --window 10 --out correlation.md
   ```
   Exit 0: record found and every compared field matches. `--all` lists every
   event in the window. Tests: `python -m unittest discover -s tests` (11,
   synthetic fixtures).
