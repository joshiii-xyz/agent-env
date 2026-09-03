# Design

## Data model

The stable fact schema has schema_version, kind, key, state, and a sorted
string detail map. Kinds include workspace, package, dependency, module,
file, lockfile, binary, origin, cache, and warning. State is either observed
or unresolved.

## Interfaces

Which resolves a program name against PATH and retains all existing
candidates. Owner accepts an absolute or relative filesystem path and joins
it to the nearest Cargo package boundary. Module accepts dotted or Rust ::
module paths. Scan joins workspace metadata, local files, runtime tool
identities, cache roots, and bounded PATH entries.

## Input boundaries

Cargo metadata is called with --format-version=1 --no-deps --offline.
Source files are limited to an 8 MiB prefix. PATH has at most 256 entries,
directory inventory has at most 2048 entries, symlink traversal has 16 steps,
and a scan emits at most 512 records.

## Output

JSON output is a single object or array. JSON Lines output has one fact per
line and no volatile timestamps. Paths inside a workspace use a
<workspace>/... label. External paths use a short digest. Text output is a
human-readable projection of the same stable values.

## Failure behavior

Missing manifests, malformed Cargo metadata, permission errors, broken
symlinks, missing module files, absent lockfiles, and unavailable tools are
represented as unresolved results. CLI parsing and output write failures use
exit code 2. An inspection never installs or executes a package.

## Portability boundary

The data model is portable, but executable permission and PATH behavior are
implemented and validated Linux first. Windows, macOS, network filesystems,
container overlays, and procfs-specific observations are not claimed as
tested behavior.
