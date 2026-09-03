# Release

The 0.1.0 MVP was published to crates.io and released on GitHub on
2026-09-03. The private release record is stored under
qa/evidence/iteration-2026-09-03.md.

## Dry-run gate

Run from a clean checkout:

~~~bash
git diff --check
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --locked
cargo package --locked
cargo audit
~~~

Run the fuzz target with an explicit nightly toolchain and an outer timeout:

~~~bash
timeout --foreground 60s env RUSTUP_TOOLCHAIN=nightly cargo fuzz run fact -- -max_total_time=10
~~~

Record the command, duration, corpus, execution count, and result privately
under qa/evidence/. Do not commit generated fuzz output.

## Version consistency

Check Cargo.toml, Cargo.lock, CHANGELOG.md, README.md, and the tag before
publishing. The crate name is agent-env and the executable name is agent-env.

## Publication order

~~~text
local gate
installed binary smoke test
review and commit
push main
hosted CI, security, and CodeQL
cargo publish --dry-run --locked
cargo publish --locked
verify registry availability
push annotated tag
wait for release package workflow
verify public install and smoke test
record private evidence
~~~

Do not publish a registry version before its package contents are final.
Published versions are immutable. Yank or deprecate only through the
registry's documented process, then publish a new version after a complete
gate.
