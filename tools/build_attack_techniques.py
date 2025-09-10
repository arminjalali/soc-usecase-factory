import json, csv
from pathlib import Path
root = Path(__file__).resolve().parents[1]
stix = root/"mappings/raw/enterprise-attack.json"
out  = root/"mappings/generated/attack_techniques_master.csv"

objs = json.loads(stix.read_text(encoding="utf-8")).get("objects", [])
rows = []
for o in objs:
    if o.get("type") != "attack-pattern": 
        continue
    if o.get("x_mitre_deprecated") or o.get("revoked"):
        continue
    tid = None
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and r.get("external_id"):
            tid = r["external_id"]; break
    if not tid: 
        continue
    tactics = sorted({kp["phase_name"] for kp in o.get("kill_chain_phases", [])
                      if kp.get("kill_chain_name") == "mitre-attack"})
    rows.append({"technique_id": tid, "technique_name": o.get("name",""),
                 "tactics_csv": ",".join(tactics)})

rows.sort(key=lambda r: (r["technique_id"].split('.')[0], r["technique_id"]))
out.parent.mkdir(parents=True, exist_ok=True)
with out.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["technique_id","technique_name","tactics_csv"])
    w.writeheader(); w.writerows(rows)
print(f"Wrote {out} with {len(rows)} techniques")
