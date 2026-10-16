#!/bin/bash
# Corporate SOC Simulation - deploy Nimbrek detection rules on the Wazuh manager.
# Installs the custom rules as their own file so the Home SOC Lab rules in
# local_rules.xml stay untouched. Validates the config before restarting.
set -e
RULES=/var/ossec/etc/rules
RAW=https://raw.githubusercontent.com/ddiazcr/corporate-soc-simulation/main/rules/local_rules.xml

echo "== Backing up local_rules.xml =="
cp "$RULES/local_rules.xml" "/root/local_rules.xml.$(date +%Y%m%d-%H%M%S).bak"

echo "== Removing any previous Nimbrek group from local_rules.xml =="
# Drop an older inline Nimbrek block if a past run appended one.
sed -i '/<group name="nimbrek/,/<\/group>/d' "$RULES/local_rules.xml"

echo "== Downloading current Nimbrek rules =="
curl -fsSL "$RAW" -o "$RULES/nimbrek_rules.xml"
chown wazuh:wazuh "$RULES/nimbrek_rules.xml"
chmod 660 "$RULES/nimbrek_rules.xml"
echo "Rules installed: $(grep -c '<rule id' "$RULES/nimbrek_rules.xml")"

echo "== Testing manager configuration =="
if /var/ossec/bin/wazuh-analysisd -t; then
  echo "== Config OK, restarting manager =="
  systemctl restart wazuh-manager
  sleep 5
  /var/ossec/bin/wazuh-control status | grep analysisd
  echo "DEPLOY_OK"
else
  echo "DEPLOY_FAILED: config test failed, manager NOT restarted" >&2
  exit 1
fi
