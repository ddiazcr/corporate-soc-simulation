# Live validation — approval gate on Windows (PR #10, 2026-11-18)

Closes the live check of [PR #10](https://github.com/ddiazcr/corporate-soc-simulation/pull/10):
on the Windows analysis host, with the live feed reading Wazuh over SSH, each
analyst answer becomes the matching decision, an invalid answer is asked
again instead of being logged, and every decision row is linked to its case
and to the Wazuh alert id in SQLite.

Setup: Windows 11, Python 3.14, interactive PowerShell; `wazuh_feed.py --ssh
wazuhadmin@192.168.56.102 --no-dedup` at `913e768` (PR #12 branch, which
contains #10); `AI_MODE=SIMULADO`. Trigger: `klist purge` + `klist get
MSSQLSvc/db01.lab.local:1433` on DC01 (honeytoken, rule 100212, RC4).
`--no-dedup` because the five alerts share rule, addresses and content: with
dedup on, later ones would merge into the first case and no decision would be
asked. Dedup is not under test here.

## Result

| Alert (manager, UTC) | Wazuh id | Case | Typed | Decision (id) |
|---|---|---|---|---|
| 03:39:08.334 | `1795059548.1687269` | `…-801a1f14` | `a` | `approved` (67) |
| 03:40:13.376 | `1795059613.1704295` | `…-c2bcdd7b` | `a` | `approved` (68) |
| 03:47:51.310 | `1795060071.1902286` | `…-5f2b4ef6` | `r` | **`rejected`** (69) |
| 03:48:27.242 | `1795060107.1911002` | `…-01b57c47` | `x`, then `a` | `Respuesta no válida ('x')` → asked again → `approved` (70) |
| 03:49:21.369 | `1795060161.1929001` | `…-c2c6f46f` | `s` | **`skipped`** (71) |

- `a → approved`, `r → rejected`, `s → skipped` ✅; invalid input re-asked, not logged ✅.
- Every case has exactly one decision; every Wazuh id is linked to its case with
  state `atendida`; totals 71 cases / 71 decisions. Raw query:
  [`sqlite-decisions.txt`](sqlite-decisions.txt) (`feed_procesadas` ⋈ `casos` ⋈ `decisiones`).
- No action is executed on any answer: the gate only records the decision.

**Recorded as typed.** The plan was `a`, `r`, then invalid + `s`. On the second
alert `a` was typed instead of `r`, and after the `x` the analyst typed `a`
instead of `s`; both are kept as logged (`approved`). Two more triggers then
produced `rejected` and `skipped`. The audit log is not edited after the fact.

Between the second and third alerts the feed was stopped and restarted; the
restart began at the saved cursor and did not replay the two handled alerts
(PR #12 behaviour).

## Files

| File | What it shows |
|---|---|
| `p10-a-approved.png` | First alert, `a` → `approved` |
| `p10-r-rejected.png` | `r` → `rejected` |
| `p10-invalid-reask.png` | `x` → `Respuesta no válida` → asked again |
| `p10-s-skipped.png` | `s` → `skipped` |
| `sqlite-decisions.txt` | Decision ↔ case ↔ Wazuh id |

Screenshots are unedited terminal captures.
