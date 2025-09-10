import csv
from pathlib import Path

root = Path(__file__).resolve().parents[1]
tech_csv = root/"mappings/generated/attack_techniques_master.csv"
stype_csv= root/"inventory/botsv3_sourcetypes.csv"
wevt_csv = root/"inventory/botsv3_eventcodes.csv"
out_csv  = root/"mappings/generated/mapping_scaffold.csv"

present = set()
if stype_csv.exists():
    with stype_csv.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            for k in ("sourcetype","Sourcetype","sourceType"):
                if k in r and r[k]:
                    present.add(r[k].strip()); break

evt = set()
if wevt_csv.exists():
    with wevt_csv.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            for k in ("EventCode","eventcode","event_code"):
                if k in r and r[k]:
                    evt.add(str(r[k]).strip()); break

def any_prefix(prefixes):
    pl = tuple(p.lower() for p in prefixes)
    return [s for s in present if s.lower().startswith(pl)]

families = []
win = any_prefix(("wineventlog", "xmlwineventlog", "wineventlog:", "winhostmon", "PerfmonMk".lower()))
if [s for s in present if "WinEventLog" in s or "XmlWinEventLog" in s or "WinHostMon" in s or "PerfmonMk" in s]:
    families.append(("Windows Security/Sysmon", "|".join(sorted(
        [s for s in present if s.lower().startswith(("wineventlog","xmlwineventlog")) or
                              "winhostmon" in s.lower() or "perfmonmk" in s.lower()]))))
asa = any_prefix(("cisco:asa",))
if asa: families.append(("Cisco ASA", "|".join(sorted(asa))))
ct = any_prefix(("aws:cloudtrail",))
if ct: families.append(("AWS CloudTrail", "|".join(sorted(ct))))
gd = [s for s in present if "guardduty" in s.lower()]
if gd: families.append(("AWS GuardDuty", "|".join(sorted(gd))))
vpc = [s for s in present if "vpcflow" in s.lower()]
if vpc: families.append(("AWS VPC Flow", "|".join(sorted(vpc))))
s3  = any_prefix(("aws:s3:accesslogs",))
if s3: families.append(("AWS S3 Access Logs", "|".join(sorted(s3))))
o365= [s for s in present if "o365" in s.lower()]
if o365: families.append(("Microsoft 365/O365", "|".join(sorted(o365))))
aad = [s for s in present if "aad" in s.lower()]
if aad: families.append(("Azure AD", "|".join(sorted(aad))))
ntw = any_prefix(("bro:","zeek:","stream:"))
if ntw: families.append(("Network Telemetry (Zeek/Stream)", "|".join(sorted(ntw))))
sep = any_prefix(("symantec:ep",))
if sep: families.append(("Symantec EP", "|".join(sorted(sep))))
c42 = [s for s in present if "code42" in s.lower()]
if c42: families.append(("Code42", "|".join(sorted(c42))))
lin = [s for s in present if s.lower().startswith(("linux","syslog","unix"))]
if lin: families.append(("Linux Syslog", "|".join(sorted(lin))))

win_markers = {
    "T1078": ["4624","4625","4768","4769","4776","4672"],
    "T1133": ["4624","4648","4776"],
    "T1059": ["4688"],
    "T1053": ["4698"],
    "T1543": ["7045","7036"],
    "T1070": ["1102"],
    "T1531": ["4740"],
}
VIS_GAP_TACTICS = {"reconnaissance","resource-development"}

rows = []
with tech_csv.open(encoding="utf-8") as f:
    for t in csv.DictReader(f):
        tid = t["technique_id"]; name = t["technique_name"]
        tactics = [x.strip().lower() for x in t["tactics_csv"].split(",") if x.strip()]
        for fam_name, sts in families:
            markers, telemetry, gap = "", "Unknown", ""
            if fam_name.startswith("Windows"):
                ids = win_markers.get(tid.split('.')[0], [])
                if ids:
                    markers = "EventCode=" + "/".join(ids)
                    telemetry = "Yes" if any(x in evt for x in ids) else "Maybe"
                else:
                    telemetry = "Maybe"
            else:
                telemetry = "Yes"
            if any(t in VIS_GAP_TACTICS for t in tactics):
                gap = "Visibility gap (outside enterprise telemetry)"

            rows.append({
                "technique_id": tid,
                "technique_name": name,
                "tactics": t["tactics_csv"],
                "log_source_family": fam_name,
                "sourcetypes": sts,
                "event_markers": markers,
                "telemetry_present": telemetry,
                "gap_type": gap,
                "notes": ""
            })

out_csv.parent.mkdir(parents=True, exist_ok=True)
with out_csv.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=[
        "technique_id","technique_name","tactics","log_source_family","sourcetypes",
        "event_markers","telemetry_present","gap_type","notes"
    ])
    w.writeheader(); w.writerows(rows)

print(f"Wrote {out_csv} rows={len(rows)}")
