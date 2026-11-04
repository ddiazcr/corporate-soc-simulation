#!/bin/bash
# Set the system clock from the HTTPS Date header of a well-known site.
# For lab VMs that drift after the host sleeps or a saved state is resumed and
# have no NTP daemon. Accurate to about a second - enough for Kerberos (5 min
# tolerance) and for coherent SIEM timelines.
set -e
NOW=$(curl -sI https://www.google.com | grep -i '^date:' | cut -d' ' -f2- | tr -d '\r')
[ -n "$NOW" ] || { echo "Could not read time from the web"; exit 1; }
echo "Before: $(date -u)"
date -u -s "$NOW" >/dev/null
hwclock -w 2>/dev/null || true
echo "After:  $(date -u)"
