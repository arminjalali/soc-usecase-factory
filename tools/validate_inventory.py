#!/usr/bin/env python3
import csv, re, sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
devices = root/"inventory"/"devices.csv"
stypes  = root/"inventory"/"botsv3_sourcetypes.csv"

REQ = ["device_id","vendor","product","platform","version","location","ip_or_scope",
       "log_transport","log_format","index","sourcetype","enabled","owner_group",
       "mitre_tactics","mitre_techniques","sample_raw","sample_parsed","notes"]

def load_sourcetypes(path):
    s = set()
    with path.open(encoding="utf-8", errors="replace") as f:
        r = csv.DictReader(f)
        col = next((c for c in r.fieldnames if c and c.lower().strip()=="sourcetype"), r.fieldnames[0])
        for row in r:
            if row.get(col): s.add(row[col].strip())
    return s

def validate_devices(path, sourcetypes):
    ok = True
    with path.open(encoding="utf-8", errors="replace") as f:
        r = csv.DictReader(f)
        if r.fieldnames != REQ:
            print("[ERROR] devices.csv header mismatch.")
            print("Expected:", REQ)
            print("Got     :", r.fieldnames)
            ok = False
        i=1
        for row in r:
            i+=1
            for k in ("device_id","vendor","product","platform","index","sourcetype","enabled"):
                if not row.get(k):
                    print(f"[FAIL] line {i}: '{k}' empty"); ok=False
            st = row.get("sourcetype","").strip()
            if st and st not in sourcetypes:
                print(f"[WARN] line {i}: sourcetype '{st}' not in botsv3_sourcetypes.csv")
            en = (row.get("enabled","") or "").lower()
            if en not in ("true","false","yes","no","1","0"):
                print(f"[WARN] line {i}: enabled='{row.get('enabled')}' not boolean-ish")
            mts = [m.strip() for m in (row.get("mitre_techniques","") or "").split(",") if m.strip()]
            for m in mts:
                if not re.match(r"^T\d{4}(\.\d{3})?$", m):
                    print(f"[WARN] line {i}: bad mitre_techniques id '{m}'")
    return ok

sourcetypes = load_sourcetypes(stypes)
print(f"[INFO] sourcetypes present: {len(sourcetypes)}")
res = validate_devices(devices, sourcetypes)
print("[RESULT] devices.csv:", "PASS" if res else "FAIL")
