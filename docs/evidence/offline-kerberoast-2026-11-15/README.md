# Evidence — offline investigation of the live 100212 alert (2026-11-15)

Analysis and conclusion: [investigation report](../../investigations/kerberoast-honeytoken-2026-11-15/).

| File | What it is | SHA-256 |
|---|---|---|
| `SHA256SUMS.txt` | Hash of `DC01-Security-window.evtx`, written on DC01 by the export script | — |
| `DC01-kerberos-logon-window.json` | 583 Kerberos/logon events (4768/4769/4770/4771/4624/4625/4634/4672) from that EVTX, parsed by `Get-WinEvent` | `4c7c4201…6d7d` |
| `hayabusa-timeline.jsonl` | Hayabusa 4.4.0 `dfir-timeline -t jsonl -w -O`, bundled rules: 92 detections, 13 unique | `0edfef1a…5b38` |
| `hayabusa-run.txt` | Hayabusa's terminal summary (rule counts, 89 / 46,480 events with hits); ANSI colours and banner removed | — |
| `correlation.md` | Output of `correlate_alert_evtx.py` on the files above (exit 0: 14/14 fields match) | — |

**Not in the repo:** `DC01-Security-window.evtx` (38.9 MB, 46,480 events,
2026-11-15 19:58–23:51Z by event time). Kept on the analysis host;
its SHA-256 `3b837a9367718b820adcb8efdfc3f8f564fa23c961506d5a065142c465f387e0`
was computed on DC01 and matched after the copy. `sha256sum -c SHA256SUMS.txt`
next to that file verifies it.

Lab data only: `lab.local` accounts, host-only addresses (192.168.56.0/24), lab
domain SIDs.
