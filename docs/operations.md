# Operations

## Installation

Build or install locally with cargo install --path . Run the binary from the
project directory when using implicit Cargo manifest discovery. Pass
--manifest-path when the inspected project is elsewhere.

## Safe execution

The scanner is read-only and invokes Cargo metadata with --offline. Review
the output before sharing it. Do not run a report through a tool that treats
its strings as shell commands.

## Logging and retention

The CLI writes reports only when --output PATH is supplied. It reads the
written file back and compares it with the intended content. Keep reports and
private QA logs under a local ignored directory and delete them through the
operator's normal recoverable cleanup process.

## Troubleshooting

An unresolved manifest means no readable Cargo.toml was found. An unresolved
package can mean the path is outside a known workspace or that Cargo metadata
could not be produced offline. An unresolved cache means only that the
observed root is absent or inaccessible. Run with an explicit manifest and
inspect the text projection before drawing conclusions.

## Recovery

Agent-env does not mutate project state, so there is no product rollback or
database recovery path. If an output path was selected incorrectly, preserve
the original report and write a new report to a reviewed path.
