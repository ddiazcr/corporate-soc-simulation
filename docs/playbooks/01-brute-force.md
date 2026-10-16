# Playbook 01 — Brute force (T1110.001)

**Goal:** hammer one domain account with a wordlist from Kali and fire rule
**100200** (chains off built-in 60204, level 12) with a real attacker source
IP (`192.168.56.103`).

| | |
|---|---|
| Technique | T1110.001 — Brute Force: Password Guessing |
| Source | Kali `192.168.56.103` |
| Target | DC01 `192.168.56.10`, account `nimbrek\jdoe` (any valid user) |
| Windows event | 4625 (logon failure, logon type 3) |
| Detection | built-in 60204 → custom **100200** |

## 1. Prepare

```bash
# Small list ending in one correct password is optional; wrong-only is enough
printf '%s\n' Summer2024 Password1 Welcome1 Autumn2024 Nimbrek123 Hunter2 \
  > passwords.txt
```

## 2. Attack

Over SMB with NetExec (clear, one account, many tries):

```bash
netexec smb 192.168.56.10 -u jdoe -p passwords.txt --no-bruteforce
```

`--no-bruteforce` pairs the single user with each password in order (true
password guessing, not a full cross-product). 8+ failures in 240 s is what
trips 60204.

## 3. What to expect on the DC

Each failure logs **4625** with:

- `LogonType` **3** (network),
- `SubStatus` **0xC000006A** (wrong password) — if you see **0xC0000064**
  the username does not exist; **0xC0000072** the account is disabled,
- `IpAddress` = `192.168.56.103`.

## 4. Validate the detection

```bash
# On the manager — the custom rule, not just the native 60204
sudo jq -c 'select(.rule.id=="100200")
            | {t:.timestamp, level:.rule.level,
               src:.data.win.eventdata.ipAddress}' \
     /var/ossec/logs/alerts/alerts.json
```

Expected: rule `100200`, level `12`, `src = 192.168.56.103`.

If only `60204` appears and not `100200`, re-check that the rule file is
deployed as `nimbrek_rules.xml` and passes `wazuh-logtest` with a pasted 4625
event (see [../hunting-queries.md](../hunting-queries.md)).

## 5. Capture evidence

- `alerts.json` line → [`../../samples/4625-bruteforce.json`](../../samples/)
  (anonymized).
- Dashboard alert → `../img/` as `21-alert-100200-bruteforce.png`.
- Flip T1110.001 to ✅ in [`../mitre_attack_mapping.md`](../mitre_attack_mapping.md)
  once the capture shows **100200** (not 60204).
