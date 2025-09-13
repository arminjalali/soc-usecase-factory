#!/usr/bin/env python3
"""
Seed a mapping scaffold that links your inventory sourcetypes to ATT&CK techniques.

Inputs:
  inventory/devices.csv
  inventory/schemas/**.yaml  (optional but recommended)
  inventory/samples/*.csv    (optional; used to point to examples)
  mappings/generated/attack_techniques_master.csv

Output:
  mappings/generated/mapping_scaffold.csv

Columns:
  technique_id,technique_name,tactics_csv,platform,sourcetype,index,
  key_fields_csv,example_sample,confidence,status,notes

Notes:
- technique_id is left blank for curation (human step). If you want auto-suggestions,
  enable the --auto-hints flag to populate 'notes' with suggested IDs (not set by default).
"""
from __future__ import annotations
import argparse, csv, glob, os, re, sys
from pathlib import Path

SCHEMA_FIELD_LIMIT = 10

def read_devices(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            if row.get("sourcetype"):
                rows.append(row)
    return rows

def read_schema_fields(schema_path: Path) -> list[str]:
    """tiny YAML reader for our 3-key schema lines."""
    if not schema_path or not schema_path.exists():
        return []
    fields = []
    cur = None
    for line in schema_path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith("- name:"):
            name = s.split(":",1)[1].strip()
            cur = {"name":name}
            fields.append(name)
        elif s.startswith("type:") or s.startswith("description:"):
            continue
    return fields

def find_schema_for_sourcetype(schemas_root: Path, sourcetype: str) -> Path|None:
    for p in schemas_root.rglob("*.yaml"):
        # cheap header check
        head = p.read_text(encoding="utf-8", errors="ignore")[:2000]
        if f"sourcetype: {sourcetype}" in head:
            return p
    return None

def sanitize(st: str) -> str:
    return re.sub(r"[:/\\\s]+", "_", st).strip("_")

def guess_platform(sourcetype: str) -> str:
    st = sourcetype.lower()
    if st.startswith(("wineventlog", "xmlwineventlog", "perfmon", "script:")):
        return "windows"
    if st.startswith("aws:"):
        return "cloud"
    if st.startswith("ms:o365") or st.startswith("ms:aad") or "o365" in st:
        return "saas"
    if st.startswith(("cisco:", "stream:","bro:","zeek:")):
        return "network"
    if st.startswith(("symantec:ep", "osquery")):
        return "edr"
    if st.startswith(("unix:", "linux_")) or ("linux" in st and "wineventlog" not in st):
        return "linux"
    return "other"

def load_attack_master(path: Path) -> dict[str, dict]:
    m = {}
    with path.open("r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            m[r["technique_id"]] = r
    return m

def main():
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser()
    ap.add_argument("--devices", default=str(root/"inventory/devices.csv"))
    ap.add_argument("--schemas", default=str(root/"inventory/schemas"))
    ap.add_argument("--samples", default=str(root/"inventory/samples"))
    ap.add_argument("--attack", default=str(root/"mappings/generated/attack_techniques_master.csv"))
    ap.add_argument("--out",    default=str(root/"mappings/generated/mapping_scaffold.csv"))
    ap.add_argument("--auto-hints", action="store_true", help="Add heuristic suggestions to 'notes' (does not set technique_id)")
    args = ap.parse_args()

    devices = read_devices(Path(args.devices))
    if not devices:
        print(f"[ERROR] No rows in {args.devices}", file=sys.stderr); sys.exit(2)
    schemas_root = Path(args.schemas)
    samples_root = Path(args.samples)
    attackm = load_attack_master(Path(args.attack))

    # Prepare rows: one row per sourcetype in devices.csv (not per technique yet).
    # Curation will duplicate rows for multi-technique coverage.
    seen = set()
    out_rows = []
    for d in devices:
        st = d["sourcetype"].strip()
        idx = (d.get("index") or "").strip()
        if not st or st in seen:
            continue
        seen.add(st)

        platform = guess_platform(st)
        schema_path = find_schema_for_sourcetype(schemas_root, st)
        fields = read_schema_fields(schema_path)[:SCHEMA_FIELD_LIMIT] if schema_path else []
        key_fields_csv = ",".join(fields)

        sample_name = sanitize(st) + ".csv"
        sample_path = samples_root / sample_name
        example_sample = str(sample_path) if sample_path.exists() else ""

        notes = ""
        if args.auto_hints:
            # very light hints; won’t set technique_id, just suggest
            s = st.lower()
            hints = []
            if s.startswith("aws:cloudtrail"):
                hints += ["T1078", "T1098", "T1484", "T1110"]
            if "sysmon" in s:
                hints += ["T1059", "T1003.001", "T1105", "T1047", "T1041"]
            if "wineventlog:security" in s:
                hints += ["T1078", "T1110", "T1053", "T1543"]
            if s.startswith("cisco:asa"):
                hints += ["T1046", "T1110", "T1071"]
            if "aad" in s and "signin" in s:
                hints += ["T1078", "T1098", "T1110"]
            if "o365" in s and "management" in s:
                hints += ["T1114", "T1098"]
            if hints:
                notes = f"suggested: {','.join(sorted(set(hints)))}"

        out_rows.append({
            "technique_id": "",                 # leave blank for curation
            "technique_name": "",
            "tactics_csv": "",
            "platform": platform,
            "sourcetype": st,
            "index": idx,
            "key_fields_csv": key_fields_csv,
            "example_sample": example_sample,
            "confidence": "low",
            "status": "candidate",
            "notes": notes
        })

    out_path = Path(args.out); out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "technique_id","technique_name","tactics_csv","platform","sourcetype","index",
            "key_fields_csv","example_sample","confidence","status","notes"
        ])
        w.writeheader(); w.writerows(out_rows)

    print(f"[OK] wrote {out_path} rows={len(out_rows)}")

if __name__ == "__main__":
    main()
