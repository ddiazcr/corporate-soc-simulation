# Log samples

Anonymized real events captured from the lab, so anyone reading the repo can
see the raw data a detection fires on without rebuilding the environment.

## How to populate

For each validated attack, pull the matching line(s) from the manager and
drop them here with a descriptive name:

```bash
# Example: Kerberoasting
sudo jq -c 'select(.rule.id=="100210")' \
     /var/ossec/logs/alerts/alerts.json | head -3 > 4769-kerberoasting.json
```

Suggested files (one per technique, named by event + attack):

| File | From | Technique |
|---|---|---|
| `4625-bruteforce.json` | rule 100200 | T1110.001 |
| `4625-spraying.json` | rule 100201 | T1110.003 |
| `4769-kerberoasting.json` | rule 100210/100211 | T1558.003 |
| `4728-group-change.json` | rule 100220 | T1098 |

## Anonymize before committing

This repo is a portfolio. Scrub anything environment-specific that is not part
of the lab's public story:

- Replace real usernames with the lab personas (`jdoe`, `svc-sql`, …).
- Keep the lab IPs (`192.168.56.0/24`) — they are private and part of the
  design.
- Remove agent keys, internal hostnames you do not want public, and any
  non-lab data.

Keep the JSON structure intact (`rule`, `data.win.system`,
`data.win.eventdata`) so the field paths in
[`../docs/hunting-queries.md`](../docs/hunting-queries.md) still line up.
