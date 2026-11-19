# Live validation — the feed resumes after a stop (PR #12, 2026-11-18)

Closes the live check of [PR #12](https://github.com/ddiazcr/corporate-soc-simulation/pull/12):
an alert written to `alerts.json` **while the feed was stopped** is read on
restart, and a review interrupted **after the case was saved but before the
analyst decided** resumes on the same case. The result is one case, one
decision and the Wazuh alert id linked to both in SQLite.

Code under test: `feat/feed-resume` at `913e768`. On the analysis host (Windows 11,
Python 3.14) the suite passed first: `Ran 97 tests … OK (skipped=18)`.
`AI_MODE=SIMULADO`: the subject is the resume logic, not the model, so the
verdict is the fixed simulated one (no API call, no cost). Telegram was live.

## Result

| Check | Expected | Observed |
|---|---|---|
| First start records a resume point before any alert | `feed_cursor` row, no case | inode 945752, byte 768176; 65 cases / 65 decisions (baseline unchanged) |
| Alert fired during the pause is after that point | end offset > 768176, same inode | Wazuh id `1795058621.1289840`, ends at byte 783620, inode 945752 |
| Restart reads it from the cursor | remote reader starts at `945752 768176` | ✅ (`t3`), case `23742fbbbf29b189-a8c56acd` created, Telegram notice |
| Stop at the approval prompt leaves case + link, no decision | link `en_revision`, 0 decisions, cursor not past the alert | ✅ link `en_revision`; case and link saved 6 ms apart (same transaction); cursor 779078 = start of the alert line |
| Restart resumes the review on the same case | "retomando la revisión del caso …", no new triage | ✅ (`t4`), no new `>>> Wazuh` line for that alert |
| Final state | 1 case, 1 decision, link `atendida`, cursor past the alert | ✅ decision `approved` (id 66), link `atendida`, cursor 937579; only one case since the baseline; 66 / 66 |

Raw output of the final query: [`sqlite-final-state.txt`](sqlite-final-state.txt).

## Timeline (UTC)

| Time | Clock | Event |
|---|---|---|
| 03:22:39.74 | analysis host | Feed stopped after the first start; resume point 945752:768176 saved |
| 03:22:37.39 | DC01 | Event 4769, record 258219: `Administrator` requests `MSSQLSvc/db01.lab.local:1433` (`svc_sql_backup`), RC4 `0x17`, client `::1` |
| 03:23:41.637 | Wazuh manager | Alert 100212 level 12, agent 004, id `1795058621.1289840`, written to `alerts.json` |
| 03:28:54.80 | analysis host | Restart: case `23742fbbbf29b189-a8c56acd` + link `en_revision` committed together; feed stopped at the prompt |
| 03:32:29.56 | analysis host | Restart: review resumed on the same case; decision `approved`; link `atendida` |
| 03:33:18.02 | analysis host | Feed stopped; cursor 945752:937579 |

**Clocks.** The analysis host and the manager agreed (manager `date -u`
03:13:21 at 21:13 local; it is no longer frozen at 2026-11-11). DC01 ran
about one minute behind them: its event time (03:22:37) reads earlier than the
feed stop (03:22:39) although the ticket was requested after the stop, and the
manager wrote the alert at 03:23:41. The proof that the alert came after the
resume point does not rely on clocks: it rests on byte offsets in the same
file (783620 > 768176, inode 945752).

## Why the cursor moved from 768176 to 779078 while the review was pending

Non-NIMBREK alerts written before the honeytoken alert were read and skipped;
the feed records the position of the last line fully handled, so it advanced
over them and stopped at the start of the pending alert's line (779078; the
alert ends at 783620). Already-handled lines are not read again; the pending
alert was.

## Files

| File | What it shows |
|---|---|
| `t1-first-start-and-stop.png` | First start (`Sin punto de retoma`), stop |
| `t2-dc01-honeytoken-during-pause.png` | `klist get` on DC01 with the feed stopped: RC4 service ticket |
| `t3-restart-recovers-alert-stop-at-prompt.png` | Remote reader started at `945752 768176`; alert 03:23:41; stop at the prompt |
| `t3-telegram.png` | Notification for case `…-a8c56acd` |
| `t4-resume-review-same-case-approved.png` | Remote reader at `945752 779078`; review resumed on the same case; `approved` |
| `sqlite-final-state.txt` | Final SQLite query |

Screenshots are unedited terminal and chat captures.

## Reproduce

1. Back up `casos_ad.db`; record counts and `feed_cursor`.
2. `python wazuh_feed.py --ssh <user>@<manager>`; wait; Ctrl+C.
3. With the feed stopped, on DC01: `klist purge` then `klist get MSSQLSvc/db01.lab.local:1433`.
4. On the manager, list NIMBREK alerts after the saved byte offset and note the Wazuh id.
5. Restart the feed; at the approval prompt press Ctrl+C. Check: link `en_revision`, no decision.
6. Restart; answer `a`; stop. Check: one case, one decision, link `atendida`, cursor past the alert.
