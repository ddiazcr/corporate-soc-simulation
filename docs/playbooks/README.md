# Attack playbooks — Nimbrek S.A.

Step-by-step runbooks to execute each Phase 3 attack **from Kali
(`192.168.56.103`) against DC01 (`192.168.56.10`)** and validate that the
matching Wazuh rule fires. Running the attacks from a separate host is what
gives the alerts a real attacker source IP, instead of the DC attacking
itself.

> **Scope.** This is a closed, Host-Only lab (`lab.local`) built to practise
> Blue Team detection. Only run these commands against your own lab VMs.

## Order

Each playbook is self-contained, but this order builds evidence from simplest
to hardest:

1. [Brute force (T1110.001)](01-brute-force.md) — rule **100200**
2. [Password spraying (T1110.003)](02-password-spraying.md) — rules **100201 / 100203**
3. [Kerberoasting (T1558.003)](03-kerberoasting.md) — rules **100210 / 100211**
4. [Privileged group change (T1098)](04-privileged-group-change.md) — rule **100220**

## Before you start

- **Audit policies** are applied on DC01 (`scripts/Enable-AuditPolicies.ps1`).
- The **custom rules** are deployed and validated with `wazuh-logtest`
  (see [`docs/hunting-queries.md`](../hunting-queries.md) and the install
  header in `rules/local_rules.xml`).
- Kali has Impacket and NetExec:
  ```bash
  pipx install impacket        # GetUserSPNs.py, etc.
  sudo apt install netexec     # or pipx install netexec
  ```

## The evidence loop (every playbook ends here)

For each attack, capture the alert from the manager so the detection is
provable without rebuilding the lab:

```bash
# On the Wazuh manager — confirm the custom rule fired
sudo jq -c 'select(.rule.id=="<RULE_ID>")
            | {t:.timestamp, rule:.rule.id, level:.rule.level,
               mitre:.rule.mitre.id, src:.data.win.eventdata.ipAddress,
               user:.data.win.eventdata.targetUserName}' \
     /var/ossec/logs/alerts/alerts.json
```

Save the JSON line under [`../../samples/`](../../samples/) (anonymized) and a
dashboard screenshot under [`../img/`](../img/), then update the Status column
in [`../mitre_attack_mapping.md`](../mitre_attack_mapping.md).
