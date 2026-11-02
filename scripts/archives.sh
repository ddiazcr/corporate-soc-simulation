#!/bin/bash
# Toggle Wazuh event archiving (logall_json) for debugging.
# With it on, EVERY event the manager receives is written to
# /var/ossec/logs/archives/archives.json, whether or not a rule alerted on it.
# That separates "the event never reached the manager" from "it arrived but no
# rule matched it". Turn it off afterwards: archives grow fast.
#   usage: archives.sh on | off
set -e
CONF=/var/ossec/etc/ossec.conf
MODE="${1:-on}"
[ "$MODE" = "on" ] && NEW=yes || NEW=no

cp "$CONF" "/root/ossec.conf.$(date +%Y%m%d-%H%M%S).bak"
if grep -q '<logall_json>' "$CONF"; then
  sed -i "0,/<logall_json>[a-z]*<\/logall_json>/s//<logall_json>$NEW<\/logall_json>/" "$CONF"
else
  sed -i "0,/<global>/s//<global>\n    <logall_json>$NEW<\/logall_json>/" "$CONF"
fi
grep -m1 '<logall_json>' "$CONF"
/var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager && echo "ARCHIVES_$MODE"
