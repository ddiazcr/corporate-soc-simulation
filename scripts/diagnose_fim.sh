#!/bin/bash
# Diagnose why the accessibility-backdoor rule (100240, T1546.008) is not firing.
# Walks the FIM chain backwards: any FIM alerts from the DC at all -> any for the
# accessibility helpers -> which rule classified them -> is 100240 loaded.
A=/var/ossec/logs/alerts/alerts.json
R=/var/ossec/etc/rules/nimbrek_rules.xml

echo "== 1. FIM (syscheck) alerts from DC01, last 5 =="
grep '"name":"DC01"' "$A" | grep '"syscheck"' | tail -5 | jq -c '{t:.timestamp, rule:.rule.id,
  desc:.rule.description, path:.syscheck.path, event:.syscheck.event}'

echo; echo "== 2. FIM alerts mentioning an accessibility helper =="
grep -iE 'sethc|utilman|osk\.exe|magnify|narrator|displayswitch' "$A" | grep '"syscheck"' | tail -5 |
  jq -c '{t:.timestamp, rule:.rule.id, path:.syscheck.path, changed:.syscheck.changed_attributes}'

echo; echo "== 3. Rule 100240 loaded =="
grep -A3 'rule id="100240"' "$R" | head -4

echo; echo "== 4. Latest DC01 alert of any kind (is the agent sending?) =="
grep '"name":"DC01"' "$A" | tail -1 | jq -c '{t:.timestamp, rule:.rule.id, desc:.rule.description}'
