# agent-env

Agent-env exposes a read-only, machine-readable view of local executable,
package, module, file, lockfile, and source-origin relationships.

Status: published 0.1.0 MVP

CI: https://github.com/joshiii-xyz/agent-env/actions/workflows/ci.yml
Release: https://github.com/joshiii-xyz/agent-env/releases/tag/v0.1.0

## Install

Install the published binary:

~~~bash
cargo install agent-env --version 0.1.0 --locked
~~~

## Quick start

~~~bash
agent-env which cargo
agent-env owner ./target/debug/tool
agent-env scan --format jsonl
~~~

## What it solves

Agent-env answers where a command will be found, which Cargo package owns a
file, which module source file is selected, and which local source origin
supports a package or lockfile. It records unresolved evidence instead of
turning missing metadata into a confident answer.

## How it works

The which operation searches PATH in order, checks executable permissions,
and follows bounded symlink chains. Owner locates a Cargo manifest and joins
its offline Cargo metadata with the requested path. Module resolves declared
Rust file modules from Cargo target roots. Scan emits sorted JSON Lines facts
for workspace packages, dependencies, targets, files, lockfiles, toolchain
identities, Cargo cache roots, and visible PATH binaries.

## CLI commands or library API

~~~text
agent-env which PROGRAM [--format text|json]
agent-env owner PATH [--manifest-path PATH] [--format text|json]
agent-env module MODULE [--manifest-path PATH] [--format text|json]
agent-env scan [--manifest-path PATH] [--format jsonl|json|text] [--output PATH]
agent-env version
~~~

The Rust library exposes resolve_program, inspect_owner_path,
inspect_module_path, scan_project, and render_facts.

## Output and exit codes

JSON and JSON Lines records use schema version 1. JSON Lines records are
sorted by kind, key, state, and detail map. State is observed or unresolved.
Exit code 0 means the requested inspection completed, including when the
report contains unresolved facts. Exit code 2 means CLI or inspection input
could not be processed.

## Safety, privacy, and data handling

The product is read-only. It does not install, remove, modify, or execute
packages. Cargo metadata is invoked with --offline. The scanner reads only
the specific Cargo and filesystem metadata needed for its report. It does not
read credential files or dump the process environment. External paths are
represented by short digests in scan output, URLs with credentials are
redacted, and secret-like values are never emitted.

## Limits and non-goals

This release supports Cargo projects on Linux first. It does not prove package
ownership for files outside a known Cargo boundary, reconstruct all module
forms, or infer a dependency from an absent provenance record. PATH and source
file inspection are bounded. Rustup internals, Python environments, package
installation, hosted services, and the word agent as a product category are
outside scope. See docs/limits.md.

## Testing and development

~~~bash
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --locked
cargo package --locked
cargo audit
~~~

The bounded fuzz target parses JSON Lines facts. See CONTRIBUTING.md and
docs/release.md for the change and release gates.

## Release and support status

Version 0.1.0 is published on crates.io and released on GitHub. It is a
Linux-first MVP limited to evidence-backed local inspection and makes no
production-readiness claim.

## Contributing

Read CONTRIBUTING.md before proposing a change. Keep new observations
deterministic, bounded, and explicit about uncertainty.

## License

Agent-env is released under the MIT License.
