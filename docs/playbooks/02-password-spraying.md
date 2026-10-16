# Playbook 02 — Password spraying (T1110.003)

**Goal:** try one password across many accounts (staying under lockout) and
fire rule **100201** (NTLM/SMB) and/or **100203** (Kerberos). Both are level
13 so they outrank 100200 on the same burst.

| | |
|---|---|
| Technique | T1110.003 — Brute Force: Password Spraying |
| Source | Kali `192.168.56.103` |
| Target | DC01 `192.168.56.10`, 6+ accounts |
| Windows event | 4625 (NTLM) / 4771 (Kerberos) |
| Detection | **100201** (NTLM) / 100202 → **100203** (Kerberos) |

## 1. Prepare a user list

6+ real domain accounts (the rules need the **same source IP** failing
against **different target users**):

```bash
printf '%s\n' jdoe asmith mlopez rgarcia pvargas ktorres > users.txt
```

## 2a. NTLM / SMB spray (fires 100201)

```bash
# one password, many users, one attempt each
netexec smb 192.168.56.10 -u users.txt -p 'Winter2025!' --no-bruteforce
```

On the DC: 4625, LogonType 3, `SubStatus 0xC000006A`, **different**
`TargetUserName` per event, same `IpAddress`.

## 2b. Kerberos spray (fires 100202 → 100203)

```bash
# kerbrute: pre-auth spray, generates 4771 (not 4625)
kerbrute passwordspray -d lab.local --dc 192.168.56.10 users.txt 'Winter2025!'
```

On the DC: 4771 with `Status 0x18` (bad password). Rule 100202 classifies each
4771; 100203 escalates on 6+ accounts in 120 s.

## 3. Validate

```bash
sudo jq -c 'select(.rule.id=="100201" or .rule.id=="100203")
            | {t:.timestamp, rule:.rule.id, level:.rule.level,
               src:.data.win.eventdata.ipAddress}' \
     /var/ossec/logs/alerts/alerts.json
```

Expected: `100201` (SMB path) or `100203` (Kerberos path), level 13.

> **Note the overlap.** A spray of 8+ attempts also trips 60204/100200. Seeing
> both is correct — document it. The level-13 spraying alert is the one that
> should dominate triage because the *fan-out across accounts* is the real
> signal.

## 4. Lockout safety

Check the domain lockout threshold first so the spray does not lock accounts:

```powershell
Get-ADDefaultDomainPasswordPolicy | Select LockoutThreshold, LockoutObservationWindow
```

Keep attempts-per-account below `LockoutThreshold` within the observation
window (one attempt each, as above, is safe for any non-zero threshold).

## 5. Capture evidence

- `alerts.json` lines → [`../../samples/`](../../samples/).
- Dashboard → `../img/`.
- Flip T1110.003 to ✅ in [`../mitre_attack_mapping.md`](../mitre_attack_mapping.md).
