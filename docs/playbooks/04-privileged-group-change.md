# Playbook 04 — Privileged group manipulation (T1098)

**Goal:** add a member to a privileged group on DC01 and fire rule **100220**
(level 13), which keeps only *additions* (4728 / 4732 / 4756) to
Administrators, Domain Admins, Schema Admins or Enterprise Admins.

| | |
|---|---|
| Technique | T1098 — Account Manipulation |
| Source | DC01 `192.168.56.10` (post-compromise action) |
| Windows event | 4728 (global) / 4732 (local) / 4756 (universal) |
| Detection | built-in 60154/60159/60166/60167 → custom **100220** |

This is a post-exploitation action, so run it on the DC as an admin (it
simulates an attacker who already holds privilege and is establishing
persistence).

## 1. Trigger (on DC01)

```powershell
# Simulated attacker adds a low-priv account to Domain Admins -> event 4728
Add-ADGroupMember -Identity "Domain Admins" -Members jdoe

# Clean up immediately after capturing the alert
Remove-ADGroupMember -Identity "Domain Admins" -Members jdoe -Confirm:$false
```

Adding to the built-in **Administrators** local group instead produces 4732;
a universal group produces 4756. Rule 100220 covers all three.

## 2. What to expect

Event **4728** with:

- `TargetUserName` = the group (`Domain Admins`),
- `MemberName` / `MemberSid` = the account added,
- `SubjectUserName` = who did it.

The built-in privileged-group rule fires first (level 12); 100220 chains off
it and raises to level 13 while dropping *removal* events.

## 3. Validate

```bash
sudo jq -c 'select(.rule.id=="100220")
            | {t:.timestamp, level:.rule.level,
               group:.data.win.eventdata.targetUserName,
               by:.data.win.eventdata.subjectUserName}' \
     /var/ossec/logs/alerts/alerts.json
```

Expected: rule `100220`, level `13`.

## 4. (Optional) tighten the rule

If you want to alert only on the most sensitive groups by SID rather than by
the built-in parent, add a `field` match on `win.eventdata.targetSid`:

- `-512` Domain Admins
- `-519` Enterprise Admins
- `-544` Administrators
- `-518` Schema Admins

## 5. Capture evidence

- `alerts.json` line → [`../../samples/4728-group-change.json`](../../samples/).
- Dashboard → `../img/`.
- Flip T1098 to ✅ in [`../mitre_attack_mapping.md`](../mitre_attack_mapping.md).
