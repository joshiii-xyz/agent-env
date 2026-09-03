# Local operating contract

Build with cargo build --locked. Format with cargo fmt --all -- --check.
Run cargo test --all-targets --locked, Clippy with
cargo clippy --all-targets --all-features --locked -- -D warnings, docs with
RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --locked, packaging with
cargo package --locked, and audit with cargo audit.

The authoritative implementation is src/lib.rs; CLI entry is src/main.rs.
The Cargo lockfile, tests, docs, and workflows are part of the change
boundary. The MVP is a read-only Linux-first Cargo and filesystem inspector.
Package installation, credential reads, network fetches, hosted services, and
human usability testing are out of scope.

Before editing, plan and define success. Make only scoped edits. Read back
changed files. Run relevant validation commands and record exact results.
Never place secrets in tracked files or logs. Verify output writes by reading
the complete file back. Commit and push only after the release or change gate
passes.
