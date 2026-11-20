# Live Kerberoasting detection from the network (2026-11-15)

Closes the gap open since 2026-11-11 ([roadmap item 3](../../roadmap.md)): a
Kerberoasting request launched from Kali, through the DC01 agent, raises rule
100212. This is a live attack ingested by the real agent, not an event
injected on the manager (see the [engine test](../engine-test-2026-11-15/) for
that).

| File | What it is |
|---|---|
| `live_kerberoast_alert.json` | The full Wazuh alert for the live request |
| `alerts-json-live-vs-injected.jpg` | `alerts.json` showing the live alert (agent 004) next to the injected ones (agent 000) |

## Attack

From Kali (192.168.56.103), a domain user (`crojas`) requested the service
ticket for the honeytoken SPN `MSSQLSvc/db01.lab.local:1433` with Impacket's
`GetUserSPNs -request`. The service ticket came back RC4-encrypted (`0x17`,
`$krb5tgs$23$`), which is the Kerberoasting tripwire: the honeytoken keeps RC4
on purpose so any request for its ticket stands out.

The DC's clock was ~2 h behind and Kali's clock had to be set to the DC's UTC
to get past `KRB_AP_ERR_SKEW` before the ticket was issued — a lab clock
problem, not part of the detection. The Wazuh manager's clock was also frozen
at 2026-11-11, which is why the alert timestamp reads that date.

## Alert

| Field | Value |
|---|---|
| Rule | 100212, level 12 |
| MITRE | T1558.003 Kerberoasting (Credential Access) |
| Agent | 004 · DC01 · 192.168.56.10 |
| Event | 4769, `eventRecordID` 256462, `DC01.lab.local` |
| Service | `svc_sql_backup` |
| Client address | `::ffff:192.168.56.103` (Kali) |
| Ticket encryption | `0x17` (RC4) |
| Requested by | `crojas@LAB.LOCAL` |
| Decoder | `windows_eventchannel` |

## Live vs injected

The screenshot lists every 100212 alert for `svc_sql_backup`. The injected
events of the engine test are on **agent 000** (`wazuh-server`, the manager)
with `eventRecordID` 9xxxxxxxxx; the live request is the only one on **agent
004** (`DC01`) with an ordinary `eventRecordID` (256462). That distinction is
what makes this the live detection and not a replay of the injected test.

```
... agente 000  wazuh-server  recordID 9094422450  regla 100212 0x17   (injected)
2026-11-11T19:28:28.602+0000  agente 004  DC01  recordID 256462  regla 100212 0x17   (live)
```

## Reproduce

With the AI feed stopped, from a terminal inside the manager:

```bash
sudo tail -n0 -f /var/ossec/logs/alerts/alerts.json \
  | grep --line-buffered -E '"id":"1002(10|11|12)"' \
  | python3 -u -c 'import sys,json
for l in sys.stdin:
    a=json.loads(l); e=a["data"]["win"]["eventdata"]
    print(a["timestamp"], a["rule"]["id"], a["agent"]["id"], e.get("ipAddress"), e.get("ticketEncryptionType"), flush=True)'
```

Then, from Kali, request the honeytoken ticket with a valid domain account and
confirm a line with `100212`, agent `004`, `::ffff:192.168.56.103`, `0x17`.
