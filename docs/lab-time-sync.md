# Lab time synchronisation

Why it matters here: the Wazuh manager stamps every alert with its own clock,
Kerberos tolerates 5 minutes of skew, and the investigations correlate SIEM
alerts with DC01 events. Several write-ups had to work around a manager clock
that was days behind (29 h 45 min on 2026-11-20, about 6 days 17 h on
2026-11-25). This page records the fix of 2026-11-25/26 and what is still
open. Raw outputs: [`evidence/clock-sync-2026-11-25/terminal-outputs.txt`](evidence/clock-sync-2026-11-25/terminal-outputs.txt).

## Design

One source of truth, no guest on the internet:

```
Windows host (Windows time, internet)
  └─ VBoxService (VirtualBox Guest Additions) ─→ DC01 192.168.56.10
                                                  └─ NTP (w32time, served from DC01's clock) ─→ Wazuh manager 192.168.56.102 (chrony)
Kali: net time set -S <dc> before Kerberos work (unchanged)
```

## What was found

- **Manager:** no time service running (`NTP service: inactive`, no
  `systemd-timesyncd`), but `chrony` 4.8 installed. Its `chrony.conf` has no
  `include`/`confdir`/`sourcedir` line, so files dropped in `conf.d/` or
  `sources.d/` are **not read**; settings go in `chrony.conf` itself.
- **Manager had internet access.** Enabled with its default config, chrony
  synchronised to public servers. The VM had a second adapter, **NAT**
  (`enp0s8`, 10.0.3.15, MAC 08:00:27:19:F9:56), next to the host-only one.
  This contradicted the documented design (SIEM on an isolated host-only
  network; the model is never called from it). Since when it was attached is
  not known.
- **DC01:** w32time serves its **local CMOS clock** (`LOCL`, stratum 1, root
  dispersion 10 s). VBoxService was running with its default thresholds, under
  which small drift is only slewed slowly.

## What was changed

| Where | Change | How |
|---|---|---|
| Manager clock | Set once from the host's UTC | `$t = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'); ssh -t wazuhadmin@192.168.56.102 "sudo date -u -s '$t' && sudo hwclock -w"` |
| Manager network | **NAT adapter cable disconnected** (VirtualBox → Wazuh server → Network → Adapter 2 → *Virtual Cable Connected* off). Host-only adapter unchanged. `enp0s8` now `NO-CARRIER`. | VirtualBox GUI |
| Manager chrony | Public pools commented out; `server 192.168.56.10 iburst prefer`; `makestep 1 -1` (step on any offset over 1 s, not only at start-up, so a restored VM corrects itself); `maxdistance 16` (accept DC01, which announces 10 s dispersion); service enabled at boot | `sed`/`tee` on `/etc/chrony/chrony.conf`, `systemctl enable --now chrony` |
| DC01 VBoxService | `--timesync-set-threshold 1000` (step when over 1 s instead of 20 min) and `--timesync-set-on-restore 1` | `VBoxManage guestproperty set DC01-v2 /VirtualBox/GuestAdd/VBoxService/… ` from the host, then `Restart-Service VBoxService` on DC01 |

## Result and what is still open

**Status: partial correction; synchronisation to DC01 not yet demonstrated.**

- **Manager clock: corrected once, by hand.** Its offset went from about 6
  days 17 hours to within the few seconds an SSH-based check can resolve
  (host 05:34:51.2Z, manager 05:34:57.4Z read after the SSH login). That
  correction came from setting the clock from the host, not from chrony.
- **Manager ↔ DC01 via chrony: configured, not shown working.** In the last
  check `chronyc sources` listed DC01 as `^~ 192.168.56.10 … +51.9s … +/- 10.2s`:
  reachable (reach 377) but marked `~`, *too variable*, so not the selected
  source (`*`) per the [chrony 4.8 documentation](https://chrony-project.org/doc/4.8/chronyc.html#sources).
  `Leap status: Normal` and a small `System time` in `chronyc tracking` do not
  override that: they reflect an earlier selection, not that the clock is
  tracking DC01 now. Whether chrony follows DC01, and how far the manager and
  DC01 clocks are apart, is therefore **not established**; neither is that
  SIEM and DC timestamps agree.
- **DC01: still off by seconds, not yet stable.** `w32tm /stripchart` from the
  host measured DC01 at −11.6 to −14.4 s at 23:35 and −5.9 to −10.8 s at 23:57
  (Costa Rica time), with jumps of about 5 s between samples two seconds
  apart. The VBoxService change brought it down from about 57 s but does not
  hold it within a second. The jumps suggest two mechanisms adjusting the clock
  (VBoxService and w32time); a hypothesis, not yet established. That DC01
  jumps would also explain chrony marking it too variable.
- **To call it resolved:** a joint capture of `chronyc -n sources -v` and
  `chronyc tracking`, repeated after several polls, showing `^*` on
  192.168.56.10 and an acceptable offset; plus a `w32tm /stripchart` of DC01
  against the host without jumps.
- Next option if needed: serve NTP from the Windows host on the host-only
  adapter and point DC01's w32time at it (and turn VBoxService time sync
  off), so DC01 has one adjuster and an external reference.
- **Updates now need the NAT cable.** Without internet, package updates and
  Wazuh's online vulnerability feeds do not reach the manager; reconnect the
  cable only for that, then disconnect it.

## Check

```powershell
# host: manager vs host, and chrony's view of DC01
(Get-Date).ToUniversalTime().ToString('o'); ssh wazuhadmin@192.168.56.102 'date -u +%FT%T.%NZ; chronyc -n sources; chronyc tracking | grep -E Reference\|System\|Leap; ip -br link show enp0s8'
# host: DC01 vs host
w32tm /stripchart /computer:192.168.56.10 /samples:5 /dataonly
```

PowerShell 5 strips inner double quotes when it passes a quoted command to
`ssh`; the commands above avoid them (single quotes doubled as `''` where
needed).
