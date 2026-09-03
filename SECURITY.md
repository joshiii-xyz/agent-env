# Security policy

Agent-env is a local, read-only inspector. Reports can reveal project names,
package versions, source relationships, and local state. Treat reports as
private evidence.

Do not submit credentials, private paths, full environment dumps, or generated
qa output in an issue. Report a suspected vulnerability privately to the
repository owner before public disclosure.

The scanner uses offline Cargo metadata, bounded file reads, path redaction,
and explicit unresolved states. These controls reduce accidental disclosure
but do not make a report safe for unrestricted publication.
