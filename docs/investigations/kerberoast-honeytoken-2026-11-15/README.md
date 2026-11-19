# Offline investigation — Kerberoasting on the honeytoken (alert 100212, 2026-11-15)

> **Status: analysed.** Raw DC01 Security log exported and hashed on the DC
> (2026-11-18), Hayabusa 4.4.0 timeline, field-by-field correlation with the
> Wazuh alert, native fields and audit result of the records Hayabusa added,
> AD objects resolved on DC01. Open: operator confirmation that the password
> reset of `crojas` was authorised.

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
| `DC01-Security-window.evtx` (38.9 MB, 46,480 events, 2026-11-15 19:00–23:59Z) | Raw records, independent of Wazuh | SHA-256 `3b837a93…387e0` computed on DC01, re-checked after the copy; kept off the repo for size, hash published |
| `DC01-kerberos-logon-window.json` (583 events) | 4768/4769/4770/4771/4624/4625/4634/4672 parsed by `Get-WinEvent` | [published](../../evidence/offline-kerberoast-2026-11-15/) |
| `hayabusa-timeline.jsonl` (92 detections, 13 unique) | Hayabusa 4.4.0, bundled rules, `dfir-timeline -t jsonl -w -O` | [published](../../evidence/offline-kerberoast-2026-11-15/) |
| `DC01-native-records.json` (90 records) | The Kali chain plus every event of logon sessions `0x37072c`, `0x39e0f5` (from .103) and `0x9f14e` (`Administrator`), with `Keywords` (audit success/failure); by [`extract_native_records.ps1`](extract_native_records.ps1) | [published](../../evidence/offline-kerberoast-2026-11-15/) |
| `ad-object-resolution.txt` | The 4662 object and GUIDs resolved against this domain on DC01, and the object's audit SACL | [published](../../evidence/offline-kerberoast-2026-11-15/) |
| [`correlation.md`](../../evidence/offline-kerberoast-2026-11-15/correlation.md) | Output of [`correlate_alert_evtx.py`](correlate_alert_evtx.py) | regenerated from the files above |

Chain of custody: export script copied to DC01 and hash-checked against the repo
blob (`fd4d7fcd…8ef4`); EVTX hashed on DC01 before leaving it; same hash after
the copy. Hayabusa ZIP hash matched GitHub's published digest
(`ec267006…bf339`); extractor hash-checked against the repo (`ec924667…558e`).

`TaskDisplayName` in `DC01-native-records.json` was rendered on the analysis
host and is wrong for some events (a 4724 shows "Kerberos Service Ticket
Operations"); the analysis relies on `EventId` and raw `Keywords`
(`0x8020…` Audit Success, `0x8010…` Audit Failure).

## 1. Alert vs raw record

All **14 compared fields match** between the Wazuh alert and EventRecordID
256462 in the raw log: record, event 4769, computer, time, account
`crojas@LAB.LOCAL`, service `svc_sql_backup` and its SID, client
`::ffff:192.168.56.103` port 59238, ticket options `0x40810010`, encryption
`0x17` (RC4), status `0x0`, logon GUID. Reported by the correlator; the input
files are published so the match can be re-run independently.

## 2. Timeline

Times are DC01's clock (UTC). Events from 192.168.56.103, for `crojas`, or in
the same logon sessions.

| Time | Event (result) | What it shows |
|---|---|---|
| 21:29:00 | 4625 `Administrator` (failure) | NTLM network logon from .103, wrong password (`0xc000006a`), no workstation name |
| 21:29:30, 21:29:41 | 4625 `crojas` ×2 (failure) | Same, for `crojas` |
| 21:30:31.948–.972 | 4661 → 4738 → **4724** (success) | `Administrator` opens `SAM_DOMAIN`, changes `crojas` (`PasswordLastSet` 1:30:31 PM DC local) and **resets its password**. Session `0x9f14e`: interactive on DC01 — desktop activity since 19:59 (taskhostw, DeviceCensus, 5379 credential reads), user-initiated logoff 4647 at 21:46:56; its logon predates the export window |
| 21:31:04.559 | 4624 `crojas` (success) | NTLM network logon from .103, session `0x37072c` |
| 21:31:04.620 | 4662 (success) | In that session: **Read Property** (`0x10`) on `adm_backup_legacy`, the discovery decoy — `objectCategory`, `servicePrincipalName`, `userAccountControl` |
| 21:31:04.650, .960 | 4771 ×2 (failure) | Kerberos pre-auth fails: **clock skew** (`0x25`); session ends 21:31:04.996 (4634) |
| 21:37:36.252 | 4624 `crojas` (success) | NTLM network logon from .103, session `0x39e0f5` |
| 21:37:36.259 | 4662 (success) | Same read of the decoy's three attributes |
| 21:37:36.305 | 4768 (success) | TGT for `crojas`, RC4 (`0x17`) |
| 21:37:36.327 | **4769 → alert** (success) | Service ticket for `svc_sql_backup`, RC4 — Hayabusa *Possible Kerberoasting (RC4)* and *Kerberoasting Activity – Initial Query* (medium); session ends 21:37:36.341 |

## 3. Analyst conclusion

**True positive: Kerberoasting attempt against the honeytoken (T1558.003) from
192.168.56.103 with the account `crojas`, preceded by wrong-password attempts
(T1110) from the same host. Account discovery over LDAP (T1087.002) is a
supported hypothesis, not a measured fact.**

What the log supports, and how far:

- **The ticket.** A real 4769 for the honeytoken SPN, RC4, issued (`0x0`), to
  `crojas` from .103. The honeytoken has no legitimate use, so the request alone
  is high-fidelity.
- **Breadth, within what was exported.** In the whole exported window
  (19:58–23:51 by event time) there is one 4769 from .103, for one service. That
  describes this window on this DC; ruling out a wider sweep needs a search over
  other DCs and a longer period.
- **Discovery.** Both sessions from .103 read, on the decoy `adm_backup_legacy`
  (no SPN, disabled), the attributes `objectCategory`, `servicePrincipalName` and
  `userAccountControl` — the attributes an LDAP search for accounts with an SPN
  evaluates. Only this object carries a Read-Property audit SACL (Everyone,
  Success), so the 4662 proves the search reached the decoy but cannot measure
  how many objects it read. Hence T1087.002 as hypothesis.
- **The password reset.** `Administrator` reset `crojas`'s password
  successfully (4724 Audit Success, 4738 `PasswordLastSet`) from an interactive
  session on DC01, 33 s before the first successful logon from .103. Without a
  confirmed authorisation this justifies escalation and a review of that
  session; it does not by itself show that the session was compromised.
- **Sequence.** In the 21:37:36 session: NTLM logon → decoy read → RC4 TGT →
  RC4 TGS within 75 ms, no workstation name. The 21:31:04 session shows the
  logon and the decoy read, then Kerberos failing on clock skew. The attribute
  set and order are consistent with an SPN-query tool such as Impacket's
  `GetUserSPNs`; that attribution is an inference, not something the log states.
- **Not seen.** Offline cracking leaves no trace on the DC; the ticket is treated
  as exposed (the honeytoken's password is not used anywhere).

## Verify before escalating

| Check | Status | Why it matters |
|---|---|---|
| Raw record matches the alert | ✅ 14/14 (reported) | The alert is evidence-backed |
| 4724 result | ✅ Audit Success, with 4738 `PasswordLastSet` | The reset took effect |
| **Authorisation of the reset** (session `0x9f14e`, interactive on DC01) | ⏳ **Operator confirmation** | If not authorised: escalate and review the session; its 4624 predates 19:00Z, so re-export from an earlier start to see its origin (console or RDP, and from where) |
| Decoy read also raised Wazuh 100230 | ⏳ Check `alerts.json` for 2026-11-15 | Two independent detections of the discovery step |
| Host 192.168.56.103 | Lab inventory: Kali VM | In production: asset owner, managed or not (no workstation name in any logon) |
| Account `crojas` | Used from .103 only after the reset | Contact the owner; logons elsewhere |
| Wider scope | ⏳ Not done | Other DCs and a longer window before saying "one SPN only" |
| Clocks | DC01 ~2 h behind on 2026-11-15; the 4771 `0x25` errors are that skew | Use the event's own time; state the offset when comparing systems |

**Suggested response (for human approval; nothing executed):** confirm the reset
with its author; if unexplained, escalate, review session `0x9f14e` and its
origin, reset `crojas` and review its logons, contain 192.168.56.103. The
honeytoken and the decoy need no change.

**Lab context.** This was the authorised Kerberoasting test from Kali on
2026-11-15 ([live detection](../../evidence/live-kerberoast-2026-11-15/)); the
reset is expected to be the operator setting a known password for the test
account, which the open check records until confirmed.

## Reproduce

1. **DC01 (elevated PowerShell)** — copy [`export_dc01_evtx.ps1`](export_dc01_evtx.ps1)
   (e.g. through `\\192.168.56.10\C$`), check its SHA-256 against the repo, run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\export_dc01_evtx.ps1
   ```
   Exit 2: record 256462 rolled out of the log (circular, 256 MB; it held records
   1–258,396 on 2026-11-18). Exit 3: record outside the window.
2. **Copy and verify** — `Get-FileHash` on the copy must equal `SHA256SUMS.txt`.
3. **Hayabusa** (v4.x merged `csv-timeline`/`json-timeline` into `dfir-timeline`):
   ```powershell
   .\hayabusa-4.4.0-win-x64.exe dfir-timeline -f .\DC01-Security-window.evtx -t jsonl -o .\hayabusa-timeline.jsonl -w -O
   ```
   `-w` no wizard (all events and alerts), `-O` ISO-8601 UTC; bundled rules (do
   not run `update-rules` if the result must match this one).
4. **Native fields of chosen records** — run in the current session (with
   `powershell -File` a comma list reaches the script as one string):
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
   & .\extract_native_records.ps1 -Evtx .\DC01-Security-window.evtx `
       -RecordId 256172,256206,256230,256272,256285,256286,256288,256290,256459,256460,256461,256462 `
       -LogonId 0x37072c,0x39e0f5,0x9f14e -Out .\DC01-native-records.json
   ```
5. **Resolve AD objects and GUIDs on DC01** — `Get-ADObject -Identity <objectGUID>`;
   schema attributes by `schemaIDGUID`, property sets by `rightsGuid` under
   `CN=Extended-Rights`; `(Get-Acl "AD:<DN>" -Audit).Audit` for the SACL. Output:
   [`ad-object-resolution.txt`](../../evidence/offline-kerberoast-2026-11-15/ad-object-resolution.txt).
6. **Correlate** (Python 3, standard library):
   ```bash
   python correlate_alert_evtx.py \
     --alert ../../evidence/live-kerberoast-2026-11-15/live_kerberoast_alert.json \
     --events DC01-kerberos-logon-window.json \
     --hayabusa hayabusa-timeline.jsonl --window 10 --out correlation.md
   ```
   Exit 0: record found and every compared field matches. `--all` lists every
   event in the window. Tests: `python -m unittest discover -s tests` (14,
   synthetic fixtures).
