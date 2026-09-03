# Product brief

## Problem

Local development tools expose separate answers for PATH resolution, Cargo
package metadata, Rust module files, cache locations, and lockfiles. A
diagnostic consumer must join those answers without executing or modifying the
environment.

## Target technical users

CLI authors, build and test infrastructure maintainers, and coding-agent
tooling authors who need inspectable local state.

## Current alternatives

The shell which command, Cargo metadata, editor indexing, package-manager
cache layouts, and ad hoc scripts each answer only part of the question.

## Observed weakness

Those interfaces do not provide one bounded, deterministic graph with
explicit unresolved states and a common privacy boundary.

## Switching wedge

Start with a small read-only Rust CLI that joins standard Cargo metadata,
filesystem ownership, PATH shadowing, module declarations, and source-origin
labels. Emit JSON Lines that can be consumed without a daemon.

## MVP boundary

Support Linux-first Cargo projects, local PATH inspection, Cargo package
ownership, external Rust module files, cache-root observations, lockfile
presence, and stable schema version 1 facts.

## Non-goals

No package installation, environment management, credential access, complete
Rust name resolution, Python support, hosted service, or generic agent
product.

## Evidence and inference

Cargo metadata, filesystem metadata, PATH order, and source file declarations
are observations. Package ownership inferred from a nearest manifest is a
bounded inference. An absent record never proves that a package, dependency,
or provenance claim does not exist.
