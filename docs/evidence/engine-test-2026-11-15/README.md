# Engine test — Kerberoasting rule shadowing (PR #11, 2026-11-15)

Rules 100210/100212 checked with the real Wazuh 4.9.2 engine on the lab
manager, before and after the fix in PR #11, with
[`rules/engine_test/run_engine_test.py`](../../../rules/engine_test/run_engine_test.py)
at `64cb0af`. Run 2026-11-15 ~14:45 UTC−6 (the manager's clock was still
frozen at 2026-11-11, which is why the timestamps in the file say so).

| File | What it is |
|---|---|
| `engine_test_results.json` | Results as written by the script: target file, sha256 of the old and new rules, alerts before and after, and the two rebuilt sample events |
| `engine-test-terminal.jpg` | The run in the terminal, below the checks that found the duplicated-ID problem described at the end |

## Method (summary)

`wazuh-logtest` cannot test eventchannel events in 4.9.2, so the script sends
the events to analysisd's input socket as eventchannel messages, the same
type the agent's events arrive as. The real decoder and the loaded rules then
process them (see the script's docstring for the source references). The
samples are rebuilt from real alerts on this manager: a honeytoken ticket
request (4769, `svc_sql_backup`, RC4 `0x17`, from `::1`) and a legitimate AES
ticket (`0x12`). In a fidelity check, the alert produced by the rebuilt
honeytoken event matched the original on the compared fields: every
`data.win.eventdata` field of the original, plus the system fields `eventID`,
`providerName`, `channel`, `keywords` and `severityValue`. The JSON records this
as "campos idénticos", the wording of the script at the time; later versions
print "coincidieron los campos comparados".

The honeytoken event is sent three times, changing only the client address:

- `::1`, as captured;
- `::ffff:192.168.56.10`, the DC's own address;
- `::ffff:192.168.56.103`, the Kali host.

The manager is restarted with the rules on disk before "before", and again
after the new rules are installed. `ossec.log` is checked for duplicated rule
IDs after each restart.

## Result

| Sample | Before (`main` rules) | After (PR #11 rules) |
|---|---|---|
| honeytoken, `::1` | 100212, level 12 | 100212, level 12 |
| honeytoken, `::ffff:192.168.56.10` | **no alert** | 100212, level 12 |
| honeytoken, `::ffff:192.168.56.103` (Kali) | **no alert** | 100212, level 12 |
| AES ticket, legitimate | 60106, level 3 | 60106, level 3 (no false positive) |

"Before" reproduces the gap seen live on 2026-11-11: the two samples whose
client address holds an IPv4 produced no alert. The static analysis of the
ruleset points to the built-in level-0 rule 92651 taking them before
100210/100212 (see [roadmap item 3](../../roadmap.md)). This run does not record
which rule took each event: a level-0 match writes no alert. "After", all three reach 100212 and the legitimate AES
ticket stays out of the Kerberoasting chain. Every alert was decoded as
`windows_eventchannel`.

## Which rules were measured

| | File on the manager | sha256 | Matches |
|---|---|---|---|
| Before | `etc/rules/nimbrek_rules.xml` | `743abf68…` | `main` (`92346e5`): rule elements identical; one comment in the 100240 description differs (older FIM wording) |
| After | `etc/rules/nimbrek_rules.xml` | `6a7bcac1…` | `rules/local_rules.xml` at `0eb1dc6`, with Windows (CRLF) line endings from the analyst host's checkout |

The new rules remain installed on the manager.

## A run that is not used as evidence

An earlier run the same day also printed `OK`, but it is not evidence. That
version of the script wrote the repository file over
`etc/rules/local_rules.xml`, while the manager keeps the NIMBREK rules in
`etc/rules/nimbrek_rules.xml`. Every NIMBREK rule ID was then defined twice:
`ossec.log` reported warning 7612 for 100200–100240, and Wazuh keeps only the
first copy it loads. That run also showed the fixed behaviour in "before",
most likely because an interrupted earlier run had left the new rules loaded
in memory. It also removed the Suricata rule 100101 from `local_rules.xml`.

What followed:

- `local_rules.xml` was restored from its backup (the 100101 rule is back);
- the script now picks the one file that defines the new rule IDs and stops,
  before changing anything, if they appear in more than one file;
- it restarts the manager before measuring "before";
- it fails and restores if `ossec.log` reports a duplicated ID.

The top of the screenshot shows the checks that found the problem.

## What this does not cover

These are events injected on the manager, not a live attack. A
Kerberoasting request from Kali through the DC's agent is still pending
([roadmap item 3](../../roadmap.md)).
