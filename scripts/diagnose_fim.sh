#!/bin/bash
# Diagnose why the accessibility-backdoor rule (100240, T1546.008) is not firing.
# Walks the FIM chain backwards: any FIM alerts from the DC at all -> any for the
# accessibility helpers -> which rule classified them -> is 100240 loaded.
A=/var/ossec/logs/alerts/alerts.json
# alerts.json rotates daily (gzipped under alerts/YYYY/Mon/); read the last two
# rotated days plus the live file so a midnight rollover hides nothing.
src() { zcat -f $(ls -tr /var/ossec/logs/alerts/*/*/ossec-alerts-*.json.gz 2>/dev/null | tail -2) "$A"; }
R=/var/ossec/etc/rules/nimbrek_rules.xml

echo "== 1. FIM (syscheck) alerts from DC01, last 5 =="
src | grep '"name":"DC01"' | grep '"syscheck"' | tail -5 | jq -c '{t:.timestamp, rule:.rule.id,
  desc:.rule.description, path:.syscheck.path, event:.syscheck.event}'

echo; echo "== 2. FIM alerts mentioning an accessibility helper =="
src | grep -iE 'sethc|utilman|osk\.exe|magnify|narrator|displayswitch' | grep '"syscheck"' | tail -5 |
  jq -c '{t:.timestamp, rule:.rule.id, path:.syscheck.path, changed:.syscheck.changed_attributes}'

echo; echo "== 3. Rule 100240 loaded =="
grep -A3 'rule id="100240"' "$R" | head -4

echo; echo "== 4. Latest DC01 alert of any kind (is the agent sending?) =="
src | grep '"name":"DC01"' | tail -1 | jq -c '{t:.timestamp, rule:.rule.id, desc:.rule.description}'
