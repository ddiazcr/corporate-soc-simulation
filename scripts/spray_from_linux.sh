#!/bin/bash
# Corporate SOC Simulation - password spraying generator (runs on the Wazuh VM).
# Sends one failed SMB logon against several different lab accounts from a single
# source IP to validate T1110.003 (rule 100201) and T1110.001 (rule 100200).
# Lab use only: all attempts use a deliberately wrong password.
set -e
DC=192.168.56.10
WRONG='WrongPass#2026'
USERS=(ggomez mrojas lsolis acruz dvargas pmendez)

if ! command -v smbclient >/dev/null; then
  echo "Installing smbclient..."
  apt-get update -qq && apt-get install -y -qq smbclient
fi

echo "== Password spraying $DC - ${#USERS[@]} accounts, one wrong try each =="
for u in "${USERS[@]}"; do
  smbclient "//$DC/IPC\$" -U "lab\\$u%$WRONG" -c quit 2>&1 | grep -o 'NT_STATUS[_A-Z]*' | head -1
  echo "  tried $u"
  sleep 1
done
echo "== Brute force burst: 8 tries against one account =="
for i in $(seq 1 8); do
  smbclient "//$DC/IPC\$" -U "lab\\ggomez%$WRONG$i" -c quit >/dev/null 2>&1
done
echo "Done. Check detections with: bash verify_detections.sh"
