#!/usr/bin/env python3
"""
Generate YAML schemas for ALL sourcetypes listed in inventory/devices.csv.

Each YAML looks like:
  sourcetype: <exact sourcetype from devices.csv>
  fields:
    - name: <field>
      type: <string|integer|...>
      description: <what it means>

Files are written under <outdir>/<category>/<sanitized-sourcetype>.yaml

Categories (heuristic):
  - windows: WinEventLog*/XmlWinEventLog*/Script:*/Perfmon*
  - cloud:   aws:cloudtrail
  - saas:    ms:aad:*, ms:o365:* (or contains "o365")
  - network: cisco:asa, stream:*
  - edr:     symantec:ep*, osquery*
  - linux:   unix:*, linux_* (or contains 'linux' but not win event logs)
  - other:   everything else

Optional templates:
  --templates <dir>
  If a template exists at:
     <dir>/<category>/<filename>.yaml
  or  <dir>/<filename>.yaml
  it will be copied verbatim instead of generating defaults.
  <filename> is the sanitized sourcetype name used by this script.

Examples:
  python tools/generate_schemas_from_devices.py --devices inventory/devices.csv --outdir inventory/schemas
  python tools/generate_schemas_from_devices.py --devices inventory/devices.csv --outdir inventory/schemas --templates tools/schema_templates
"""

import argparse
import os
import re
import sys
import shutil
import pandas as pd

DEFAULT_FIELDS_BY_CAT = {
    "windows": [
        {"name":"EventCode","type":"integer","description":"Windows event ID / Sysmon event type"},
        {"name":"ComputerName","type":"string","description":"Hostname"},
        {"name":"User","type":"string","description":"User principal if present"},
        {"name":"Image","type":"string","description":"Process image path (if present)"},
        {"name":"CommandLine","type":"string","description":"Process command line (if present)"},
        {"name":"IpAddress","type":"string","description":"Source IP (if present)"},
    ],
    "network": [
        {"name":"src_ip","type":"string","description":"Source IP"},
        {"name":"src_port","type":"integer","description":"Source port"},
        {"name":"dest_ip","type":"string","description":"Destination IP"},
        {"name":"dest_port","type":"integer","description":"Destination port"},
        {"name":"protocol","type":"string","description":"Network protocol"},
        {"name":"message_id","type":"string","description":"Vendor message/ID if applicable"},
    ],
    "cloud": [
        {"name":"eventTime","type":"string","description":"Event timestamp"},
        {"name":"eventSource","type":"string","description":"Service that generated the event"},
        {"name":"eventName","type":"string","description":"Operation/API name"},
        {"name":"userIdentity.type","type":"string","description":"Identity type"},
        {"name":"sourceIPAddress","type":"string","description":"Client IP"},
        {"name":"errorCode","type":"string","description":"Error code if present"},
    ],
    "saas": [
        {"name":"CreationTime","type":"string","description":"Event time / sign-in time"},
        {"name":"Operation","type":"string","description":"Operation/Activity name"},
        {"name":"UserId","type":"string","description":"User identifier / UPN"},
        {"name":"ClientIP","type":"string","description":"Client IP"},
        {"name":"ResultStatus","type":"string","description":"Succeeded/Failed (or error code)"},
    ],
    "edr": [
        {"name":"computer_name","type":"string","description":"Endpoint name"},
        {"name":"event_type","type":"string","description":"Event category"},
        {"name":"action","type":"string","description":"Action taken"},
        {"name":"file_path","type":"string","description":"File path"},
        {"name":"file_hash","type":"string","description":"File hash (SHA1/SHA256)"},
    ],
    "linux": [
        {"name":"host","type":"string","description":"Hostname"},
        {"name":"process","type":"string","description":"Process name (if present)"},
        {"name":"user","type":"string","description":"User (if present)"},
        {"name":"message","type":"string","description":"Log message"},
    ],
    "other": [
        {"name":"host","type":"string","description":"Hostname (if present)"},
        {"name":"message","type":"string","description":"Log message"},
    ],
}

def categorize(sourcetype: str) -> str:
    st = sourcetype.lower()
    if st.startswith("aws:cloudtrail"):
        return "cloud"
    if st.startswith("ms:o365") or "o365" in st or st.startswith("ms:aad"):
        return "saas"
    if st.startswith("cisco:asa") or st.startswith("stream:"):
        return "network"
    if st.startswith("symantec:ep") or st.startswith("osquery"):
        return "edr"
    if st.startswith("unix:") or st.startswith("linux_") or (("linux" in st) and ("wineventlog" not in st)):
        return "linux"
    if st.startswith("wineventlog") or st.startswith("xmlwineventlog") or st.startswith("script:") or st.startswith("perfmon"):
        return "windows"
    return "other"

def filename_for_sourcetype(sourcetype: str) -> str:
    """
    Convert sourcetype to a nice file name:
      WinEventLog:Security -> wineventlog_security.yaml
      XmlWinEventLog:Microsoft-Windows-Sysmon/Operational -> xmlwineventlog_microsoft-windows-sysmon_operational.yaml
      cisco:asa -> cisco_asa.yaml
    """
    name = sourcetype
    name = name.replace("WinEventLog:", "wineventlog_")
    name = name.replace("XmlWinEventLog:", "xmlwineventlog_")
    name = name.replace("Script:", "script_")
    name = name.replace("Perfmon", "perfmon")
    name = name.replace(":", "_").replace("/", "_")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_").lower()
    return f"{name}.yaml"

def write_yaml(path: str, sourcetype: str, fields: list) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"sourcetype: {sourcetype}\n")
        f.write("fields:\n")
        for fld in fields:
            f.write(f"  - name: {fld['name']}\n")
            f.write(f"    type: {fld['type']}\n")
            f.write(f"    description: {fld['description']}\n")

def maybe_copy_template(templates_dir: str, category: str, filename: str, out_path: str) -> bool:
    """
    If a template exists, copy it and return True; otherwise return False.
    Checks:
      1) <templates_dir>/<category>/<filename>
      2) <templates_dir>/<filename>
    """
    if not templates_dir:
        return False
    cand1 = os.path.join(templates_dir, category, filename)
    cand2 = os.path.join(templates_dir, filename)
    for src in (cand1, cand2):
        if os.path.isfile(src):
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            shutil.copyfile(src, out_path)
            return True
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--devices", required=True, help="Path to inventory/devices.csv")
    ap.add_argument("--outdir", required=True, help="Directory to write schemas into (e.g., inventory/schemas)")
    ap.add_argument("--templates", default="", help="Optional directory with YAML templates to override defaults")
    args = ap.parse_args()

    # Load devices.csv
    try:
        df = pd.read_csv(args.devices, dtype=str).fillna("")
    except Exception as e:
        print(f"[ERROR] Could not read {args.devices}: {e}", file=sys.stderr)
        sys.exit(1)

    if "sourcetype" not in df.columns:
        print("[ERROR] devices.csv must contain a 'sourcetype' column.", file=sys.stderr)
        sys.exit(1)

    sourcetypes = sorted(df["sourcetype"].unique())
    if not sourcetypes:
        print("[WARN] No sourcetypes found in devices.csv.")
        sys.exit(0)

    total = 0
    for st in sourcetypes:
        category = categorize(st)
        filename = filename_for_sourcetype(st)
        out_path = os.path.join(args.outdir, category, filename)

        # Use template if available; otherwise write defaults
        if not maybe_copy_template(args.templates, category, filename, out_path):
            fields = DEFAULT_FIELDS_BY_CAT[category]
            write_yaml(out_path, st, fields)

        total += 1

    print(f"[OK] Wrote {total} schema file(s) under {args.outdir}")

if __name__ == "__main__":
    main()
