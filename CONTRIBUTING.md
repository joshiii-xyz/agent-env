# Contributing

Plan the change and define a testable result before editing. Keep changes
inside the project scope, read back every changed file, and run the relevant
validation commands before committing.

Use the local commands in AGENTS.md. Add unit tests for normalization and
parsing, integration tests for temporary Cargo and filesystem fixtures, and
CLI tests for exit codes and output streams. Parser boundaries must have
malformed, permission, and bounded-input coverage.

Do not add package installation, environment mutation, credential reads,
network fetches, or hosted backends to the MVP. Record exact validation output
in the private qa area. Human usability testing is excluded by the portfolio
brief.
