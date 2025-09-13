#!/usr/bin/env python3
"""
Build ATT&CK technique lookups from a STIX 2.1 Enterprise dump.

Inputs:
  mappings/raw/enterprise-attack.json

Outputs:
  mappings/generated/attack_techniques_master.csv
      technique_id,technique_name,is_subtechnique,parent_technique_id,tactics_csv,platforms_csv
  mappings/generated/lookups/mitre_techniques.csv
      technique_id,technique_name,tactics
  mappings/generated/lookups/mitre_tactic_order.csv
      tactic_id,tactic_name,order
  mappings/generated/attack_metadata.json
      {"attack_version": "...", "objects": N, "generated_utc": "..."}
"""
from __future__ import annotations
import argparse, csv, json, sys
from datetime import datetime, timezone
from pathlib import Path

def load_stix(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[ERROR] Failed reading {path}: {e}", file=sys.stderr)
        sys.exit(2)

def external_id(obj: dict, source_name: str) -> str|None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == source_name and ref.get("external_id"):
            return ref["external_id"]
    return None

def main():
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(root/"mappings/raw/enterprise-attack.json"))
    ap.add_argument("--master-out", default=str(root/"mappings/generated/attack_techniques_master.csv"))
    ap.add_argument("--tactics-out", default=str(root/"mappings/generated/lookups/mitre_tactic_order.csv"))
    ap.add_argument("--techniques-out", default=str(root/"mappings/generated/lookups/mitre_techniques.csv"))
    ap.add_argument("--meta-out", default=str(root/"mappings/generated/attack_metadata.json"))
    args = ap.parse_args()

    stix = load_stix(Path(args.src))
    objs = stix.get("objects", []) or []
    # Collect tactics (id->shortname/name) and ordering
    tactics = []
    for o in objs:
        if o.get("type") == "x-mitre-tactic":
            tactics.append({
                "tactic_id": o.get("x_mitre_shortname") or o.get("name","").lower().replace(" ","-"),
                "tactic_name": o.get("name",""),
                "order": o.get("x_mitre_deprecated") and 999 or 0  # temp; we’ll reindex later
            })
    # Stable order by name if STIX lacks explicit order
    tactics = sorted({(t["tactic_id"], t["tactic_name"]) for t in tactics})
    tactics = [{"tactic_id":tid, "tactic_name":tn, "order":i} for i,(tid,tn) in enumerate(tactics)]

    # Techniques + sub-techniques
    rows = []
    for o in objs:
        if o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = external_id(o, "mitre-attack")
        if not tid or not tid.startswith("T"):
            continue
        parent_tid = None
        is_sub = False
        if "." in tid:
            parent_tid = tid.split(".",1)[0]
            is_sub = True
        tactics_csv = ",".join(sorted({
            p.get("phase_name")
            for p in o.get("kill_chain_phases", []) or []
            if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")
        }))
        platforms_csv = ",".join(sorted(o.get("x_mitre_platforms", []) or []))
        rows.append({
            "technique_id": tid,
            "technique_name": o.get("name",""),
            "is_subtechnique": "true" if is_sub else "false",
            "parent_technique_id": parent_tid or "",
            "tactics_csv": tactics_csv,
            "platforms_csv": platforms_csv
        })

    rows.sort(key=lambda r: (r["technique_id"].split('.')[0], r["technique_id"]))

    master_out = Path(args.master_out); master_out.parent.mkdir(parents=True, exist_ok=True)
    with master_out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "technique_id","technique_name","is_subtechnique","parent_technique_id","tactics_csv","platforms_csv"
        ])
        w.writeheader(); w.writerows(rows)

    tech_out = Path(args.techniques_out); tech_out.parent.mkdir(parents=True, exist_ok=True)
    with tech_out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["technique_id","technique_name","tactics"])
        w.writeheader()
        for r in rows:
            w.writerow({
                "technique_id": r["technique_id"],
                "technique_name": r["technique_name"],
                "tactics": r["tactics_csv"]
            })

    tactics_out = Path(args.tactics_out); tactics_out.parent.mkdir(parents=True, exist_ok=True)
    with tactics_out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["tactic_id","tactic_name","order"])
        w.writeheader(); w.writerows(tactics)

    meta = {
        "attack_version": stix.get("spec_version") or stix.get("x_mitre_version") or "unknown",
        "objects": len(objs),
        "generated_utc": datetime.now(timezone.utc).isoformat()
    }
    meta_out = Path(args.meta_out); meta_out.parent.mkdir(parents=True, exist_ok=True)
    meta_out.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print(f"[OK] master={master_out} techniques={len(rows)}; tactics={len(tactics)}")
    print(f"[OK] lookups: {tech_out}, {tactics_out}")
    print(f"[OK] meta: {meta_out}")

if __name__ == "__main__":
    main()
