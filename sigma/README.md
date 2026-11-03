# Sigma rules — Corporate SOC Simulation (Nimbrek S.A.)

Portable, vendor-neutral versions of the Active Directory detections built for
this lab. The lab runs on Wazuh, so the enforced detections live in
[`../rules/local_rules.xml`](../rules/local_rules.xml); these Sigma rules are the
same detection logic expressed in the open [Sigma](https://sigmahq.io) format, so
the work is portable to Splunk, Microsoft Sentinel, Elastic, QRadar, and others.

Writing a detection once in Sigma and compiling it per-SIEM — instead of hand-
writing vendor syntax — is how detection engineering is done at scale.

## Rules

| Sigma rule | Technique | Windows event | Wazuh equivalent | Level |
|---|---|---|---|---|
| `ad_brute_force_t1110_001.yml` | T1110.001 Brute force | 4625 (8+ / IP / 4 min) | 100200 | high |
| `ad_password_spraying_t1110_003.yml` | T1110.003 Password spraying | 4625 (6+ accounts / IP / 2 min) | 100201 | high |
| `ad_kerberoasting_rc4_t1558_003.yml` | T1558.003 Kerberoasting | 4769, RC4 `0x17` | 100210 / 100211 | high |
| `ad_kerberoasting_honeytoken_t1558_003.yml` | T1558.003 Kerberoasting | 4769 for honeytoken SPN | 100212 | critical |
| `ad_account_discovery_decoy_t1087_002.yml` | T1087.002 Account discovery | 4662 on decoy object | 100230 | high |
| `ad_privileged_group_addition_t1098.yml` | T1098 Account manipulation | 4728 / 4732 / 4756 | 100220 | high |
| `ad_accessibility_backdoor_t1546_008.yml` | T1546.008 Accessibility backdoor | file change on System32 helpers | 100240 | critical |

Full detection logic, evidence and validation dates:
[`../docs/mitre_attack_mapping.md`](../docs/mitre_attack_mapping.md).

## Design notes (read before deploying)

- **Thresholds.** Brute force and spraying are count-based. The rules express the
  threshold with Sigma's aggregation `condition` (`count() by IpAddress`). Not all
  backends compile aggregations the same way; on Wazuh the equivalent correlation
  is done natively with `frequency` / `same_field` (see the XML rules).
- **Environmental dependency (account discovery).** `ad_account_discovery_decoy`
  only works because a single decoy object carries a Read-Property SACL. Event
  4662 on user objects is otherwise far too noisy to alert on. Deploy the decoy
  ([`../scripts/Setup-DiscoveryDecoy.ps1`](../scripts/Setup-DiscoveryDecoy.ps1))
  first.
- **Honeytoken name.** `ad_kerberoasting_honeytoken` matches `svc_sql_backup`.
  Change it to your own tripwire account.
- **File integrity (accessibility backdoor).** Uses a `file_event` log source
  (Sysmon event 11 or Wazuh syscheck). The helpers must be under FIM for it to
  fire.

## Converting to your SIEM

With [sigma-cli](https://github.com/SigmaHQ/sigma-cli) installed:

```bash
# validate
sigma check sigma/

# Splunk
sigma convert -t splunk sigma/ad_password_spraying_t1110_003.yml

# Microsoft Sentinel (KQL)
sigma convert -t kusto sigma/ad_kerberoasting_rc4_t1558_003.yml

# Elastic (Lucene / EQL)
sigma convert -t lucene sigma/ad_privileged_group_addition_t1098.yml
```
