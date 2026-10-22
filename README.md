# GenLayer Dependency Policy Attestor

An experimental GenLayer Intelligent Contract for consensus-based verification of public open-source dependency evidence.

## What it does

The contract records a bounded audit target: a GitHub owner, repository, ref, manifest path, policy, and optional evidence issue. It constructs the raw GitHub URL from validated identifiers, fetches the manifest, and asks the leader and validators to independently assess whether the dependency evidence satisfies the policy.

This is not a general-purpose security scanner. It does not accept arbitrary URLs, does not treat an LLM response as proof by itself, and does not make legal or production security decisions.

## Why GenLayer is useful here

Dependency manifests are public but can change after an assessment. The contract stores stable SHA-256 digests for the manifest and evidence issue. The validator repeats the fetch and semantic assessment, then compares the policy decision and both evidence digests under the Equivalence Principle. A changed manifest therefore cannot silently produce an equivalent result.

## Lifecycle

`OPEN` → `ASSESSED` → `CHALLENGED` → `FINAL`

An audit can be finalized by its creator after assessment. A challenge issue is recorded as a separate counter-evidence reference. The current prototype intentionally keeps the state machine narrow and auditable.

## Verification

The repository includes an AST lint workflow, local state tests, and mocked GenLayer Direct Mode tests. External GitHub and LLM calls are mocked in tests; no live deployment or audit result is claimed by the repository.

## Status

Pre-deployment prototype unless a deployment link is explicitly added by the maintainer. Not suitable for legal, financial, employment, or other high-stakes decisions.

## License

MIT. See [LICENSE](LICENSE).
