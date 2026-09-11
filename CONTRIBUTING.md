# Contributing plugins

Every package runs with the sofka user's permissions and inherited environment.
Review reduces risk, but does not provide a process sandbox or guarantee that an
external tool has no defects.

A plugin pull request must include its source, `plugin.toml`, README, license,
responsible maintainer, request/report fixtures, tests, and `publication.json`.
Maintainers review adapter behavior, execution and mutation flags, dependencies,
metadata, and workflow changes. Tests must use fixtures and must not need
production credentials.

Package IDs use lowercase ASCII letters, digits, and hyphens. Published versions
are immutable. Increment the semantic package version for every source or
manifest change. Keep package versions, the catalog schema version, and
`plugin.toml` schema versions independent.

To withdraw a version, change its status in `index.json` to `withdrawn`, add a
`withdrawal_reason`, and open a pull request. Do not delete its release assets.
Sofka will refuse new installations while continuing to report existing ones.

Runtime requirements belong in `publication.json` and the package README.
Installers copy ready-to-run packages; they never install external tools or run
adapter code.
