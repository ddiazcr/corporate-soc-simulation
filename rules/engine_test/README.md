# Engine test for rules 100210 / 100212

`run_engine_test.py` checks, on the real manager, which rule the engine
applies to a 4769 before and after a new `local_rules.xml` is installed, and
rolls back if the result is not the expected one. See the script's docstring
for the method and why `wazuh-logtest` cannot test eventchannel events in
4.9.2.

```powershell
# Analyst host, repo on the branch under test; stop the AI feed first
ssh wazuhadmin@192.168.56.102 "mkdir -p /tmp/nimbrek"
scp rules\local_rules.xml rules\engine_test\run_engine_test.py wazuhadmin@192.168.56.102:/tmp/nimbrek/
```
```bash
# From a terminal where sudo can prompt (Kali): on the manager
ssh wazuhadmin@192.168.56.102
sudo python3 /tmp/nimbrek/run_engine_test.py /tmp/nimbrek/local_rules.xml
```
```powershell
# Back on the analyst host: keep the evidence
scp wazuhadmin@192.168.56.102:/tmp/nimbrek/engine_test_results.json .
```

Expected after the new rules: `honeytoken-loopback`, `honeytoken-dc-fqdn` and
`honeytoken-network` -> 100212; `aes-legit` -> not 100210/100211/100212.
Live ingestion from Kali is a separate check.
