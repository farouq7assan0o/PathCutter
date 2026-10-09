# Extending PathCutter

Everything here is designed so that a new right, technique, rule or input costs one small change plus the test that
proves it. The repository fails loudly when a change forgets a place (see "What stops you forgetting").

## The map

| You want to add | Touch | Proof it works |
|---|---|---|
| a collector right / property GUID / dsacls letter | `pathcutter/data/rights.json`, then `python tools/gen_collector_table.py` | `tests/test_registry.py` (shape, edge exists, collector table is generated) |
| a new edge type (attack step) | `EdgeType` in `edges.py`, name in `pathfinder._ATTACK_EDGES` | `test_registry.py` demands abuse text, MITRE and exploitability; `syntax edges` lists it automatically |
| an AD CS technique | a block in `adcs.derive_adcs_edges`, an edge as above | one test per condition in `tests/test_adcs.py` (template: `lab()` / `lab3()`) |
| an Entra / Azure object or relation | `azure.py` (`_KIND_TYPE`, `_relationships`, `finalize_azure`), `NodeType` | `tests/test_azure.py` builds AzureHound-shaped JSON with `build()` |
| an audit rule | one `@rule` function in `hygiene.py` | `tests/test_hygiene.py` (construct a graph, assert the rule id and objects) |
| a change source (IaC, scripts) | one entry in `extractors.EXTRACTORS` and a module with `extract(text, origin, start)` | a fixture in `tests/data/iac/` and an end-to-end case in `tests/test_iac_cli.py` |
| a PowerShell cmdlet | `ps_rules.SUPPORTED` handler | `tests/test_powershell.py` and a script in `tests/data/ps_corpus/` (checked against the real PowerShell parser) |
| a policy key | `policy.py` (`_KNOWN_KEYS`, parse, evaluate) | `tests/test_modeling.py` |

## Rules that keep the model honest

* **Never silent.** A construct that changes identity or access but cannot be evaluated is reported as a warning
  (`UNMODELED`, which a policy can make blocking). Do not skip it, do not guess.
* **A missing fact is not evidence.** An uncollected flag, a registry value that was not read, a restriction list that was
  not gathered: the technique is *not* reported. Say so in the docstring and in `pathcutter syntax model`.
* **Over-report rather than under-report**, and label it (trusts, ESC15's patch level, `when:` conditions).
* **Controls never hide a finding.** They lower severity within floors and say "declared, not verified".
* Time-based rules measure against the newest activity in the collection, not today.

## What stops you forgetting

* `tests/test_registry.py`: every edge is an attack step or declared structural; attack edges explain themselves;
  every right in `rights.json` maps to a real edge; the PowerShell collector's GUID table is generated from the JSON;
  help lists every edge.
* `tests/test_engine_equivalence.py` + `tests/fuzz.py`: the production exposure engine, the incremental updates,
  the deny-aware search and the in-place probe are checked against `exposure_ref.py` and brute-force oracles. A new
  edge type that breaks an assumption shows up as a failing seed with a reproduction command.
* `tests/test_ps_ast.py`: the PowerShell extractor against the real PowerShell parser.
* `tests/test_toolkit.py`: anonymization preserves every attack path on the real datasets; it also catches a new field that leaks.

## Testing at any scale

```bash
python -m pytest                                   # ~15,000 tests, under a minute
EQUIV_SEEDS=200000 python -m pytest tests/test_engine_equivalence.py
python tests/fuzz.py --seeds 1000000 --workers 8   # ~6 minutes; prints a reproduction command per failing seed
python tests/fuzz.py --start 123456 --seeds 1      # replay one seed
python benchmarks/bench_scale.py 100000 1000000    # build / exposure / clone / retier
python benchmarks/bench_check.py 1000000 10        # a 10-change check on 1M objects (about 20 s)
python benchmarks/bench_ingest.py 200000           # SharpHound-shaped JSON ingest throughput
```

CI runs the suite on Linux and Windows and a nightly job fuzzes a million graphs.

## How the engine stays fast

`exposure.py` is a reverse search over integer-indexed state (`fastindex.py`). Trial changes (`check` evaluates each
change on its own) never copy the graph: `AttackGraph.probe()` mutates in place with a journal and rolls back exactly;
adding an edge updates only the states it improves (`fork_with_added_edges`), removing one re-attaches only the states
that used it (`fork_with_removed_edges`). `clone()` is copy-on-write. The original dictionary-based implementation is kept
as `exposure_ref.py`, the executable specification: if you change the engine, the fuzzer tells you within seconds
whether it still agrees.
