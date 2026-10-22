# Design: Dependency Policy Attestor

## Problem

Open-source release reviews often mention dependency and license requirements without preserving the exact manifest evidence used for the decision. A later edit can make a verbal approval impossible to reproduce.

## Bounded input model

Each audit accepts only GitHub path identifiers, a ref, one manifest path, a short policy, and an optional issue number. URL characters such as `:` and `?` are rejected from identifiers, so the contract remains the owner of the source URL construction.

## Evidence gates

The leader and each validator independently fetch the same raw manifest and optional GitHub issue. They compare:

1. policy decision;
2. manifest SHA-256 digest;
3. evidence-issue SHA-256 digest.

Rationale is deliberately excluded from equality because two honest model runs can explain the same stable evidence differently.

## Equivalence Principle

The validator does not merely check that the leader returned JSON. It repeats the web fetch and constrained semantic prompt, then rejects a result if the decision or either evidence digest differs.

## Limitations

This prototype does not parse every package ecosystem, resolve transitive dependencies, or guarantee that a license statement is legally correct. It is a review primitive and not a replacement for a security audit.
