# Research record

Date: 2026-09-03

## Primary sources

- [Cargo metadata](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html)
  defines the versioned JSON workspace, package, dependency, target, manifest,
  and source fields. Format version 1 is used.
- [Cargo manifest format](https://doc.rust-lang.org/cargo/reference/manifest.html)
  documents package manifests, targets, dependencies, repository metadata, and
  the boundary used by the owner lookup.
- [cargo locate-project](https://doc.rust-lang.org/cargo/commands/cargo-locate-project.html)
  documents upward manifest discovery and workspace selection.
- [Rust Command](https://doc.rust-lang.org/std/process/struct.Command.html)
  documents PATH lookup for non-absolute programs and the importance of
  explicit environment behavior.
- [Rust env split_paths](https://doc.rust-lang.org/stable/std/env/fn.split_paths.html)
  documents platform-specific PATH parsing.
- [Rust fs read_link](https://doc.rust-lang.org/std/fs/fn.read_link.html)
  documents symbolic-link inspection and its failure modes.
- [Linux proc filesystem](https://www.man7.org/linux/man-pages/man5/procfs.5.html)
  and [proc pid exe](https://www.man7.org/linux/man-pages/man5/proc_pid_exe.5.html)
  establish that Linux exposes read-only process and executable links, but
  those interfaces are not required for this MVP.

## Issues and discussions

The Rust Command documentation links to the platform-specific behavior that
can vary across operating systems. The Linux proc documentation describes
permission-sensitive executable links. No unstable internal Cargo or rustup
file is treated as a contract.

## Package and distribution signals

The local cargo search agent-env --limit 5 check returned adjacent packages
named agent-envoy, agent-envd, and converge-agent-envd, but not this exact
package. A repository search also found unrelated projects for Kubernetes
sandboxes and secret injection. These are distribution and naming signals, not
evidence of demand or willingness to pay.

## Evidence grade

Documented Cargo and Rust standard-library behavior is evidence-backed for the
interfaces cited above. Filesystem ownership, executable permission, cache
presence, and source module declarations are local observations. Inferring
that a nearest manifest fully owns every generated or linked file is a
bounded inference.

## Facts versus inference

Facts include PATH order, executable metadata, symlink targets, Cargo JSON
fields, file bytes within the read bound, and declared mod items. Inference
includes the selected package boundary, the cache origin label, and the
conclusion that a missing source file is unresolved rather than absent from
the wider environment.

## Rejected alternatives

- Executing a package to discover its origin would violate the read-only
  boundary.
- Reading Cargo or rustup private database formats would couple the product to
  undocumented layouts.
- Full Rust name resolution would exceed the MVP and duplicate compiler
  behavior.
- Capturing all environment variables would create a secret disclosure
  surface; only the PATH and documented local roots are inspected.

## Decision

Implement a deterministic, read-only Rust CLI around public Cargo metadata,
standard filesystem operations, bounded PATH inspection, and simple declared
module resolution. Use schema-versioned JSON Lines facts and explicit
unresolved states. Keep agent-env as a local inspection utility, not an
environment manager.
