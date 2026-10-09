# Vendor fixtures

`adcs_fixture.zip` is the raw collector output (13 JSON files) and `expected_edges.json` the ADCS edges and Tier Zero tags that
BloodHound Community Edition itself computed from it, extracted from SpecterOps' test fixture
`cmd/api/src/services/graphify/fixtures/Version6ADCSJSON` (https://github.com/SpecterOps/BloodHound, Apache License 2.0).
They are used as an independent oracle: `tests/test_adcs.py` requires PathCutter to agree with BloodHound on every ADCS edge and
Tier Zero tag it also models. `adcs_raw/`, `adcs_analyzed.json` and `all_analyzed.json` are working copies and are not committed.
