# Offline investigation — Kerberoasting on the honeytoken (alert 100212, 2026-11-15)

> **Status: analysed.** Raw DC01 Security log exported and hashed on the DC
> (2026-11-18), Hayabusa 4.4.0 timeline, field-by-field correlation with the
> Wazuh alert, native fields and audit result of the records Hayabusa added,
> AD objects resolved on DC01. The password reset of `crojas` was confirmed
> by the operator as part of the lab setup (2026-11-18). Follow-up checks
> closed on 2026-11-20 ([output](../../evidence/offline-kerberoast-2026-11-15/followups-2026-11-20.txt)):
> Wazuh 100230 fired on both decoy reads; session `0x9f14e` was opened by a
> console logon in the same boot as the reset; a single 4769 from .103, to the
> honeytoken, in the retained logs.

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
| `followups-2026-11-20.txt` | Wazuh 100230 search on the manager; opening of session `0x9f14e`; everything from .103 in the whole retained Security log | [published](../../evidence/offline-kerberoast-2026-11-15/) |
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
`0x17` (RC4), status `0x0`, logon GUID. **Independently verified** on 2026-11-19
by the external reviewer: the script at `64cfd32` re-run on the published JSON
files (exit 0, output identical to `correlation.md`), 14 tests passing, all
file hashes checked; every timeline row matched in the native records. The
check covers the derived JSON files, not the EVTX itself (hash published).

## 2. Timeline

Times are DC01's clock (UTC). Events from 192.168.56.103, for `crojas`, or in
the same logon sessions.

| Time | Event (result) | What it shows |
|---|---|---|
| 21:29:00 | 4625 `Administrator` (failure) | NTLM network logon from .103, wrong password (`0xc000006a`), no workstation name |
| 21:29:30, 21:29:41 | 4625 `crojas` ×2 (failure) | Same, for `crojas` |
| 21:30:31.948–.972 | 4661 → 4738 → **4724** (success) | `Administrator` opens `SAM_DOMAIN`, changes `crojas` (`PasswordLastSet` 1:30:31 PM DC local) and **resets its password**. Session `0x9f14e`: **console logon** on DC01 (4624 type 2, User32, 127.0.0.1, record 209845, 2026-11-11), same boot as the reset (System: OS started 2026-11-11 18:03:56, next shutdown 2026-11-15 21:46:54, no start between); the VM was suspended from 2026-11-11 17:38 to 2026-11-15 19:58 (VBoxService clock jump, no boot). The session ended with the shutdown that WLMS started at 21:46:54 for the expired evaluation licence (4647 at 21:46:56) |
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
- **Breadth.** In DC01's whole retained Security log (2026-11-04 to
  2026-11-20; DC01 is the lab's only DC) there are 9 events from .103, all on
  2026-11-15. A single 4769 from .103 was observed, to the honeytoken, in the
  retained logs. That counts ticket requests only: an LDAP sweep can read many
  SPNs without requesting tickets, and the scope of the LDAP query stays open
  (see *Discovery*).
- **Discovery.** In both sessions from .103 a read of the attributes
  `objectCategory`, `servicePrincipalName` and `userAccountControl` was logged on
  the decoy `adm_backup_legacy` (no SPN, disabled), compatible with an LDAP query
  related to SPNs; the exact filter is not in the log. Only this object carries a Read-Property audit SACL (Everyone,
  Success), so the 4662 proves the search reached the decoy but cannot measure
  how many objects it read. Hence T1087.002 as hypothesis. Wazuh rule 100230
  fired on both reads (alerts `1794424459.5431525`, `1794425308.5860442`): the
  discovery step was detected live, independently of this analysis.
- **The password reset.** `Administrator` reset `crojas`'s password
  successfully (4724 Audit Success, 4738 `PasswordLastSet`) from session
  `0x9f14e` — a console logon on DC01 — 33 s before the first successful logon from .103. Without a
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
| Raw record matches the alert | ✅ 14/14, independently verified against the published JSON | The alert is evidence-backed |
| 4724 result | ✅ Audit Success, with 4738 `PasswordLastSet` | The reset took effect |
| **Authorisation of the reset** (session `0x9f14e` on DC01) | ✅ Confirmed by the operator (2026-11-18): password set for the test account during the lab session | In production, an unconfirmed reset would mean escalating and reviewing the session |
| Logon type and origin of `0x9f14e` | ✅ Console logon (4624 type 2, User32, 127.0.0.1), record 209845. Same boot as the reset: Security boot marker (4624 type 0) at record 209685 just before it, System *OS started* (Kernel-General 12) at 2026-11-11 18:03:56 and no start until the shutdown of 2026-11-15 21:46:54; session activity on 2026-11-11 (records 209845–210567) and 2026-11-15 (210687–256272) | A local session on the DC, not a remote one |
| Decoy read also raised Wazuh 100230 | ✅ Both reads (records 256286, 256460) alerted, level 12 | Two independent detections of the discovery step |
| Host 192.168.56.103 | Lab inventory: Kali VM | In production: asset owner, managed or not (no workstation name in any logon) |
| Account `crojas` | Used from .103 only after the reset | Contact the owner; logons elsewhere |
| Wider scope | ✅ Whole retained log on the only DC (2026-11-04 → 2026-11-20): one 4769 from .103 | Older events were overwritten (circular log; oldest record moved from 1 to 33,517 between 2026-11-18 and 2026-11-20) |
| Clocks | VBoxService (Guest Additions) set DC01's clock after each boot and on resume (4616 / Kernel-General 1): 2026-11-11 18:04:44 → 16:04:38 (−2 h) right after the boot, then 2026-11-11 17:38:21 → 2026-11-15 19:58:48 when the suspended VM resumed. Event times on either side of a jump are not comparable; the 4771 `0x25` errors show a skew above 5 min between Kali and DC01 at 21:31 | Order by record number within one log; use each log's own boot and time-change events to place a timestamp |

**Suggested response (for human approval; nothing executed):** confirm the reset
with its author; if unexplained, escalate, review session `0x9f14e` and its
origin, reset `crojas` and review its logons, contain 192.168.56.103. The
honeytoken and the decoy need no change.

**Lab context.** This was the authorised Kerberoasting test from Kali on
2026-11-15 ([live detection](../../evidence/live-kerberoast-2026-11-15/)). The
operator confirmed that the reset of `crojas` was done during the lab session to
set a known password for the test account. With that confirmed, the case is a
true positive of an authorised test: no response action.

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
     --events DC01-kerberos-logon-window.json DC01-native-records.json \
     --hayabusa hayabusa-timeline.jsonl --window 10 --out correlation.md
   ```
   Exit 0: record found and every compared field matches. Several `--events`
   files are merged by record (a later file wins); with the native records the
   timeline also lists account-management and object-access events (4661, 4662,
   4672, 4724, 4738) of the related logon sessions. `--all` lists every event in
   the window. Tests: `python -m unittest discover -s tests` (16, synthetic
   fixtures).
7. **Follow-ups (2026-11-20)** — Wazuh 100230 search over every alerts file on
   the manager; `0x9f14e` opening found by ordering 4624 type 0 (boot) and the
   session's 4624 by record number; every event with client address .103 in the
   live Security log. Commands and output:
   [`followups-2026-11-20.txt`](../../evidence/offline-kerberoast-2026-11-15/followups-2026-11-20.txt).
