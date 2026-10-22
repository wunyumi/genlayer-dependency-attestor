# Portal submission draft

## Suggested category

Developer → Intelligent Contracts

## Suggested title

Dependency Policy Attestor — Consensus-Based Manifest Evidence Review

## Description

Dependency Policy Attestor is a standalone GenLayer Intelligent Contract for a bounded open-source dependency review workflow. A requester records one GitHub repository, ref, manifest path, optional evidence issue, and explicit policy. The contract constructs the raw GitHub source from validated identifiers, fetches the manifest and issue, and runs a constrained semantic assessment. Validators independently repeat the fetch and compare the decision plus SHA-256 digests of the manifest and issue evidence. The repository includes AST lint, local state tests, and mocked GenLayer Direct Mode tests. This is a pre-deployment prototype; no audit, live deployment, or reward claim is made unless separately documented.
