# Vendor fixtures

`adcs_fixture.zip` is the raw collector output (13 JSON files) and `expected_edges.json` the ADCS edges and Tier Zero tags that
BloodHound Community Edition itself computed from it, extracted from SpecterOps' test fixture
`cmd/api/src/services/graphify/fixtures/Version6ADCSJSON` (https://github.com/SpecterOps/BloodHound, Apache License 2.0).
They are used as an independent oracle: `tests/test_adcs.py` requires PathCutter to agree with BloodHound on every ADCS edge and
Tier Zero tag it also models. `adcs_raw/`, `adcs_analyzed.json` and `all_analyzed.json` are working copies and are not committed.

`ad_v5.zip` / `ad_v6.zip` are the raw collector output of `Version5JSON` / `Version6JSON` in the same repository, and
`expected_ad.json` holds the edges (as object-id pairs) and Tier Zero ids BloodHound computed from them; `tests/test_vendor_oracle.py`
compares our ingest with it edge by edge.

| `fic_raw.json`, `fic_expected.json` | SpecterOps/BloodHound `cmd/api/src/services/graphify/fixtures/AzureFederatedIdentityCredentials` (raw AzureHound output and BloodHound's derived `AZAuthenticatesTo` edges) | Apache-2.0, (c) SpecterOps | oracle for workload-identity-federation edges |
