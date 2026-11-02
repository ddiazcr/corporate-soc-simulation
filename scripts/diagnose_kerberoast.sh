#!/bin/bash
# Diagnose why the Kerberoasting rules (100210 / 100212) are not firing.
# Walks the chain backwards: event reaches the manager -> which rule classified
# it -> which encryption type it carried -> are the custom rules loaded.
A=/var/ossec/logs/alerts/alerts.json
R=/var/ossec/etc/rules/nimbrek_rules.xml
ARC=/var/ossec/logs/archives/archives.json

echo "== 1. Kerberos service-ticket events (4769) in alerts.json =="
echo -n "count: "; grep -c '"eventID":"4769"' "$A"
grep '"eventID":"4769"' "$A" | tail -5 | jq -c '{t:.timestamp, rule:.rule.id, lvl:.rule.level,
  svc:.data.win.eventdata.serviceName, enc:.data.win.eventdata.ticketEncryptionType,
  ip:.data.win.eventdata.ipAddress}'

echo; echo "== 2. Any alert mentioning svc_sql_backup =="
grep 'svc_sql_backup' "$A" | tail -3 | jq -c '{t:.timestamp, rule:.rule.id, lvl:.rule.level,
  id:.data.win.system.eventID, enc:.data.win.eventdata.ticketEncryptionType}'

echo; echo "== 3. Raw archive (only if logall_json is enabled) =="
if [ -f "$ARC" ]; then
  grep 'svc_sql_backup' "$ARC" | tail -2 | jq -c '{t:.timestamp, id:.data.win.system.eventID,
    enc:.data.win.eventdata.ticketEncryptionType, rule:.rule.id}'
else
  echo "archives.json not present (logall_json disabled)"
fi

echo; echo "== 4. Custom Kerberos rules loaded =="
grep -oE 'rule id="1002(10|11|12)"' "$R"
grep -A2 'rule id="100210"' "$R" | grep if_sid

echo; echo "== 5. Last 5 alerts from the DC agent (is it still sending?) =="
grep '"name":"DC01"' "$A" | tail -5 | jq -c '{t:.timestamp, rule:.rule.id, id:.data.win.system.eventID}'
