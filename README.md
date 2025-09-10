# SOC Use-Case Factory (MITRE ATT&CK × Splunk BOTSv3)

This repo operationalizes a use-case engineering workflow:
1) Inventory log sources
2) Map to MITRE ATT&CK techniques
3) Measure coverage & gaps
4) Implement detections and iterate

## Status
- ✅ Step 1: Source inventory scaffold
- ✅ Step 2: BOTSv3 Splunk exports (`inventory/botsv3_*`)
- ✅ Step 3: ATT&CK baseline & mapping scaffold (`mappings/generated/*`)
- 🔄 Step 4: Telemetry verification → coverage refresh → first detections
- ⏭️ Step 5: Use-case documentation & testing

## Layout
- `inventory/`
  - `devices.csv` — authoritative source inventory (manual, validated)
  - `botsv3_sourcetypes.csv` — export from Splunk
  - `botsv3_eventcodes.csv` — Windows event IDs seen
  - `verifications/` — proof-of-telemetry CSVs from Splunk searches
- `mappings/`
  - `raw/enterprise-attack.json` — MITRE ATT&CK (STIX 2.1)
  - `generated/attack_techniques_master.csv` — all techniques & tactics
  - `generated/mapping_scaffold.csv` — technique × log-family matrix (seeded)
  - `coverage_matrix.csv` — roll-up of telemetry vs gaps
- `rules/` — SPL detections (by platform/family)
- `tools/` — build/validate/update scripts
- `docs/` — SIEM pipeline & use-case docs

## Rebuild
```bash
python tools/validate_inventory.py
python tools/build_attack_techniques.py
python tools/seed_mapping_scaffold.py
# after exporting Splunk verification CSVs:
python tools/update_scaffold_with_verifications.py
python tools/compute_coverage_from_scaffold.py
