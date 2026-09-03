# Limits

Version 0.1.0 validation is Linux-only and uses temporary local fixtures.

- Windows and macOS behavior is untested.
- Network, NFS, WSL, overlay, FUSE, and remote filesystem behavior is
  untested.
- Real package caches with private registries and credential helpers are not
  read or validated.
- Cargo metadata can remain unresolved when a manifest or offline source is
  incomplete.
- PATH, directory, symlink, and source-file inspection is bounded.
- Rust macro expansion, include!, generated modules, re-exports, and full
  compiler name resolution are not reconstructed.
- A nearest Cargo manifest is an ownership heuristic, not proof of build
  provenance.
- An external path is hashed for output and cannot be recovered from the
  report.
- Permission-denial coverage is fixture-based and does not represent every
  Linux security policy.
- No package is installed, removed, or executed by the product.
- Python, uv, environment managers, hosted services, and human usability
  testing are outside the MVP.
