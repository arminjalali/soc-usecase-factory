import csv
from pathlib import Path
root = Path(__file__).resolve().parents[1]
scaffold = root/"mappings/generated/mapping_scaffold.csv"
out = root/"mappings/coverage_matrix.csv"

by_tech = {}
with scaffold.open(encoding="utf-8") as f:
    for r in csv.DictReader(f):
        key = (r["technique_id"], r["technique_name"])
        by_tech.setdefault(key, []).append((r["log_source_family"], r["telemetry_present"], r["gap_type"]))

rows = []
for (tid, name), entries in sorted(by_tech.items()):
    if any("Visibility gap" in g for _,_,g in entries):
        vis = "Yes"
    else:
        vis = "No"
    if any(t == "Yes" for _,t,_ in entries):
        status = "Telemetry available (detection gap until rule exists)"
    elif any(t == "Maybe" for _,t,_ in entries):
        status = "Telemetry likely (verify)"
    else:
        status = "No telemetry (visibility gap)"
    rows.append({
        "technique_id": tid,
        "technique_name": name,
        "visibility_gap_any_tactic": vis,
        "status": status,
        "sources_seen": "; ".join(f"{fam}:{telem}" for fam,telem,_ in entries)
    })

with out.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["technique_id","technique_name","visibility_gap_any_tactic","status","sources_seen"])
    w.writeheader(); w.writerows(rows)
print(f"Wrote {out}")
