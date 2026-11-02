#!/bin/bash
# Show the latest Nimbrek alerts captured by the manager, per technique.
A=/var/ossec/logs/alerts/alerts.json
for id in 100200 100201 100203 100210 100211 100212 100220 100230 100240; do
  echo "=== rule $id ==="
  grep "\"id\":\"$id\"" "$A" | tail -1 | \
    jq -c '{t:.timestamp, rule:.rule.id, lvl:.rule.level, mitre:.rule.mitre.id, desc:.rule.description}' 2>/dev/null || echo "  (none yet)"
done
