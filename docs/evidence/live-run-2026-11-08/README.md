# Live run — Kerberoasting on a honeytoken (2026-11-08)

One live run of the full chain: a Kerberos service ticket requested for the
honeytoken SPN on DC01 → Wazuh rule `100212` → AI triage feed → model verdict →
Telegram notification, with the suggested action waiting for a human.

**Single run (n = 1).** These are observations of one execution, not a
benchmark: no median or range is claimed until the scenario is repeated.

## Timeline

One clock is used for every figure: the screen recording (30 fps, so each time
is ±0.033 s). Wall-clock timestamps from DC01, the Wazuh manager and Telegram
are not combined: the hosts' clocks disagree (DC01's ticket time and the
manager's alert time are ~33 s apart, while the recording shows 1.9 s).

| | Event (what is visible on screen) | Clip time | From T0 | Frame |
|---|---|---|---|---|
| T0 | Enter on DC01: the cursor drops below `klist get MSSQLSvc/db01.lab.local:1433` | 2.667 s | 0 | [t0](t0-dc01-klist-get.jpg) |
| T1 | The feed prints `>>> Wazuh … regla 100212 (nivel 12)` | 4.567 s | **+1.90 s** | [t1](t1-alert-in-feed.jpg) |
| T2 | Telegram (desktop client) lists the new bot message, 9:37 PM | 10.933 s | **+8.27 s** | [t2](t2-telegram-received.jpg) |
| T3 | The feed prints `[métricas] latencia=5.809s` and the suggested action | 11.400 s | +8.73 s | [t3](t3-verdict-in-feed.jpg) |

- **Model analysis: 5.81 s** — reported by the pipeline itself (time of the API
  call, printed in the feed at T3). It is not independently timed here; it fits
  inside T1 → T2 (6.37 s), which also includes storing the case and sending
  the notification.
- T2 comes before T3 because the pipeline sends the notification and then
  prints to the console.
- T2 is the moment the Telegram **desktop client** shows the message; the
  phone was not recorded.

**Reproduce:** `python measure_events.py recording-unedited-38-52s.mp4`
(needs ffmpeg and Pillow). It decodes every frame and reports the first frame
where each screen region changes; each event was also checked by eye.

```
T0 Enter on DC01 (cursor drops to the next line)      clip  2.667 s   + 0.00 s from T0
T1 alert 100212 appears in the triage feed            clip  4.567 s   + 1.90 s from T0
T2 Telegram client receives the message               clip 10.933 s   + 8.27 s from T0
T3 feed prints the model verdict and metrics          clip 11.400 s   + 8.73 s from T0
```

## Evidence chain

| Stage | Artifact | Status |
|---|---|---|
| Original Windows event 4769 (anonymized) | — | ⏳ Pending: export the raw event of this run from the manager |
| Wazuh alert `100212` | [t1](t1-alert-in-feed.jpg): alert line as received (time, rule, level, source → DC) | 🟡 Partial: full alert JSON pending export |
| Model verdict | [t3](t3-verdict-in-feed.jpg) (action, latency, tokens, cost) · [Telegram message](telegram-notification.jpg) (priority `critical`, confidence `high`, MITRE T1558.003, summary) | ✅ As displayed · raw JSON from the case store pending |
| Decision after policy | The tripwire priority floor (PR #4) was **not active** in this run. The model's `critical` is already above that floor, so it would not have changed the outcome. | n/a in this run |
| Notification | [Telegram message](telegram-notification.jpg) · [t2](t2-telegram-received.jpg) | ✅ |
| Human decision | Not captured: the recording ends at the approval prompt | ⏳ Pending |

## Files

| File | What it is |
|---|---|
| `recording-unedited-38-52s.mp4` | 14 s of the original screen recording (source 38–52 s), not cut or sped up |
| `t0…t3-*.jpg`, `telegram-notification.jpg` | Frames from that recording at each event |
| `measure_events.py` | Re-measures T0–T3 from the clip |

**Publication review.** Lab-only data (fictional domain `lab.local`, host-only
addresses, test accounts). In the clip, the Telegram sidebar rows below the
bot were blurred: they showed the author's Telegram user ID and a BotFather
message preview. No API key, token or password appears.

**Software in this run.** Feed: `wazuh_feed.py` at `cd24203` (PR #3, python3
follower). Triage module: before PR #4 (no tripwire floor). Model:
`claude-haiku-4-5-20251001`.
