#!/usr/bin/env python3
"""
Compute coverage matrix and ATT&CK Navigator layers from a curated scaffold.

Inputs:
  mappings/generated/mapping_scaffold.csv
  mappings/generated/attack_techniques_master.csv

Outputs:
  mappings/coverage_matrix.csv
  mappings/generated/navigator/coverage_overall.layer.json
  mappings/generated/navigator/coverage_<platform>.layer.json   (windows, network, cloud, saas, edr, linux, other)
"""
from __future__ import annotations
import argparse, csv, json, sys, collections
from pathlib import Path

PLATFORMS = ["windows","network","cloud","saas","edr","linux","other"]

def read_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as f:
        return [r for r in csv.DictReader(f)]

def write_csv(path: Path, rows: list[dict], header: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=header)
        w.writeheader(); w.writerows(rows)

def build_layers(out_dir: Path, coverage: dict[str,set[str]], title: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    # overall
    maxv = max([len(v) for v in coverage.values()] or [1])
    layer = {
        "version":"4.5","name":title,"domain":"enterprise-attack","description":"Validated coverage",
        "techniques":[{"techniqueID": tid, "score": len(sts), "comment": ", ".join(sorted(sts))}
                      for tid, sts in sorted(coverage.items())],
        "gradient":{"colors":["#d9e8fb","#0a66ff"],"minValue":0,"maxValue":maxv}
    }
    (out_dir/"coverage_overall.layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")

def build_layers_per_platform(out_dir: Path, coverage_by_platform: dict[str,dict[str,set[str]]]):
    out_dir.mkdir(parents=True, exist_ok=True)
    for plat, cov in coverage_by_platform.items():
        maxv = max([len(v) for v in cov.values()] or [1])
        layer = {
            "version":"4.5","name":f"Coverage - {plat}","domain":"enterprise-attack",
            "description":f"Validated coverage for {plat}",
            "techniques":[{"techniqueID": tid, "score": len(sts), "comment": ", ".join(sorted(sts))}
                          for tid, sts in sorted(cov.items())],
            "gradient":{"colors":["#d9e8fb","#0a66ff"],"minValue":0,"maxValue":maxv}
        }
        (out_dir/f"coverage_{plat}.layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")

def main():
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser()
    ap.add_argument("--scaffold", default=str(root/"mappings/generated/mapping_scaffold.csv"))
    ap.add_argument("--attack",   default=str(root/"mappings/generated/attack_techniques_master.csv"))
    ap.add_argument("--matrix-out", default=str(root/"mappings/coverage_matrix.csv"))
    ap.add_argument("--layers-out", default=str(root/"mappings/generated/navigator"))
    args = ap.parse_args()

    scaffold = read_csv(Path(args.scaffold))
    if not scaffold:
        print(f"[ERROR] Empty scaffold: {args.scaffold}", file=sys.stderr); sys.exit(2)
    attack = {r["technique_id"]: r for r in read_csv(Path(args.attack))}

    # Only count rows that are curated to a technique AND marked validated
    curated = [r for r in scaffold if r.get("technique_id") and r.get("status","").lower() in ("validated","ready","done")]
    if not curated:
        print("[WARN] No validated mappings found. Output will be empty coverage matrix.")

    # coverage maps
    by_tid: dict[str,set[str]] = collections.defaultdict(set)
    by_tid_plat: dict[str,dict[str,set[str]]] = {p: collections.defaultdict(set) for p in PLATFORMS}

    for r in curated:
        tid = r["technique_id"]
        st  = r["sourcetype"]
        plat = (r.get("platform") or "other").lower()
        by_tid[tid].add(st)
        if plat not in by_tid_plat: plat = "other"
        by_tid_plat[plat][tid].add(st)

    # write matrix
    rows = []
    for tid, sts in sorted(by_tid.items()):
        ai = attack.get(tid, {})
        rows.append({
            "technique_id": tid,
            "technique_name": ai.get("technique_name",""),
            "tactics": ai.get("tactics_csv",""),
            "count_sourcetypes": len(sts),
            "sourcetypes_csv": ",".join(sorted(sts))
        })
    write_csv(Path(args.matrix_out), rows, ["technique_id","technique_name","tactics","count_sourcetypes","sourcetypes_csv"])

    # layers
    build_layers(Path(args.layers_out), by_tid, "Coverage - Overall")
    build_layers_per_platform(Path(args.layers_out), by_tid_plat)

    print(f"[OK] coverage matrix: {args.matrix_out} rows={len(rows)}")
    print(f"[OK] layers → {args.layers_out}")

if __name__ == "__main__":
    main()
