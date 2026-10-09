# Real collector output used as regression fixtures

These are genuine SharpHound outputs from *lab* environments (not production data). They are small, public and
permissively licensed, and are used by `tests/test_real_data.py` to keep the ingest honest against what current
collectors actually emit (a synthetic generator cannot do that).

| File | Source | Licence | Notes |
|---|---|---|---|
| `ESSOS_20240410083816_BloodHound-2.3.3.zip`, `NORTH_...`, `SEVENKINGDOMS_...` | https://github.com/m4lwhere/Bloodhound-CE-Sample-Data | Unlicense (public domain) | GOADv2 lab, SharpHound.exe v2.3.3, collected 2024-04-10 |
| `specterops_ad_sampledata.zip` | https://github.com/SpecterOps/BloodHound-Docs (`docs/assets/sample-data/ad_sampledata.zip`) | Apache-2.0, (c) SpecterOps | 3 domains with trusts, local permissions, ADCS escalation paths, collected 2024-03-05 |
| `entra_sampledata.zip` | https://github.com/SpecterOps/BloodHound-Docs (`docs/assets/sample-data/entra_sampledata.zip`) | Apache-2.0, (c) SpecterOps | A full AzureHound collection of a demo tenant (PhantomCorp): 230 users, 12,000+ applications and service principals, 116 roles, 3 subscriptions, VMs, function and web apps, scoped role assignments. The only real Entra/Azure data available publicly |

GOAD is the Game of Active Directory lab by Orange Cyberdefense. Neither project is affiliated with PathCutter.
