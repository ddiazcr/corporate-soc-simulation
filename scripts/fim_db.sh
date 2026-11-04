#!/bin/bash
# Show what Wazuh FIM has recorded for the accessibility helpers on an agent:
# whether each file is monitored at all, and the owner/hash/date of its last
# recorded state. Reads the manager's per-agent database directly.
#   usage: fim_db.sh [agent_id]   (default 004 = DC01)
ID="${1:-004}"
DB="/var/ossec/queue/db/${ID}.db"
[ -f "$DB" ] || { echo "No database for agent $ID at $DB"; exit 1; }
python3 - "$DB" <<'EOF'
import sqlite3, sys, datetime
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
cols = [r[1] for r in con.execute("PRAGMA table_info(fim_entry)")]
want = [c for c in ("full_path","uname","date","sha1","perm") if c in cols]
q = f"SELECT {','.join(want)} FROM fim_entry WHERE full_path LIKE ? ORDER BY full_path"
helpers = ("sethc","utilman","osk","magnify","narrator","displayswitch")
found = 0
for h in helpers:
    for row in con.execute(q, (f"%\\{h}.exe",)):
        found += 1
        rec = dict(zip(want, row))
        if "date" in rec and rec["date"]:
            rec["date"] = datetime.datetime.utcfromtimestamp(int(rec["date"])).strftime("%Y-%m-%d %H:%M:%S UTC")
        if "perm" in rec and rec["perm"]:
            rec["perm"] = str(rec["perm"])[:60] + "..."
        print(rec)
print(f"\n{found} helper file(s) recorded in FIM for agent {sys.argv[1].split('/')[-1][:-3]}")
total = con.execute("SELECT COUNT(*) FROM fim_entry").fetchone()[0]
print(f"{total} FIM entries in total for this agent")
EOF
