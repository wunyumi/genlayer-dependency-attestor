# Verification

## Local checks

The intended checks are:

```bash
python3 -m py_compile contracts/dependency_policy_attestor.py
genvm-lint lint contracts/dependency_policy_attestor.py
python tests/unit/test_dependency_logic.py
pytest tests/direct/test_dependency_policy_attestor.py -v
```

The direct tests use mocked GitHub responses and mocked LLM decisions. They do not claim live GitHub, Studio, or testnet execution.

## Scope of evidence

The CI workflow proves that the source parses, passes the GenLayer AST safety checks, and passes the repository's local and mocked Direct Mode tests. A live deployment address must be recorded separately if one is performed.
