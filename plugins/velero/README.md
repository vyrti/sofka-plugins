# velero

Three commands for [Velero](https://velero.io) backup and restore, in one
package:

| Command             | Select a          | Does                                                             | Changes the cluster    |
| ------------------- | ----------------- | ---------------------------------------------------------------- | ---------------------- |
| `:velero-inspect`   | Backup or Restore | Shows phase, timing, progress, errors and warnings.              | No                     |
| `:velero-trigger`   | Schedule          | Runs `velero backup create --from-schedule`.                     | Yes, with confirmation |
| `:velero-locations` | nothing           | Reads the BackupStorageLocations and reports whether they check. | No                     |

With rows marked (`space`) each selection command runs once per marked resource.

## Inspect backup or restore

Shows what Velero recorded for the selected Backup or Restore. A **Summary**
table holds the phase, the schedule or backup it came from, the storage
location, start and completion times, the expiration and TTL, item progress,
and the error and warning counts. Below it come the included and excluded
namespaces, the validation errors, and the failure reason, each only when
Velero filled it in.

This command runs no external tool. A Velero Backup and Restore keep their
whole result in `status`, and sofka already sends the selected object, so the
report comes from the request. Velero does not have to be installed on your
machine for it, and nothing is read from object storage.

`Progress` counts the items Velero walked, not bytes. Velero fills it while the
backup runs, so a finished backup that reports fewer items than its total was
not complete.

## Trigger backup schedule

Runs `velero backup create --from-schedule <schedule>` for the selected
Schedule. Velero names the backup after the schedule and the current time, then
runs it in the background.

The report shows that the backup was requested, not that it finished. Select
the new Backup and use `:velero-inspect` to follow it.

### Safety

- **`mutating = true`**: refused in read-only mode.
- **`confirm = true`**: sofka asks before every run.
- A `plugin:velero-trigger` [guardrail](https://github.com/nklmilojevic/sofka/blob/main/docs/safety.md)
  can deny it per context or namespace.

It is not marked dangerous. A trigger adds a backup and deletes nothing. The
costs are real but recoverable: object storage, API calls to the snapshot
provider, and load on the workloads Velero walks. A paused Schedule still
triggers, because a manual backup is often why you unpause one; the report says
that the schedule is paused.

## Backup storage locations

Reads every BackupStorageLocation in the Velero namespace with
`kubectl get backupstoragelocations.velero.io --output json`, then reports one
section per location: phase, provider, bucket and prefix, access mode, whether
it is the default, the validation interval, the last validation and sync times,
and the message Velero left when a validation failed.

The **Summary** says how many locations are available and which one is the
default. An `Unavailable` location means Velero could not reach or read the
bucket, so new backups going there will fail and old ones cannot be restored.

This command reads the context, not a selection, so it needs no resource in
view. It uses the `namespace` input, which defaults to `velero`, and not the
namespace you are browsing.

## What the adapter checks before it runs a tool

Sofka matches scopes on the resource plural only, and `backups`, `restores` and
`schedules` are plurals other APIs also serve. Before every action the adapter
checks the object sofka selected:

- `inspect` requires a `velero.io` `Backup` or `Restore`.
- `trigger` requires a `velero.io` `Schedule`, and never uses a replay.
- `locations` refuses a list holding anything but a `BackupStorageLocation`.
- Name and namespace must be present and match the object's metadata.

Anything else is refused with an error that names what was selected.

## Live activity

The adapter sends trigger and location phase messages to stderr for sofka's
activity popup. It forwards up to 64 KiB of child-tool diagnostics, then shows a
truncation notice and keeps draining. A failed activity write does not discard
the final report, including after a backup request. Child read and process
failures remain errors. Dry-run messages state that no backup is created.

## Inputs

| Command             | Input       | Default  | Purpose                                                              |
| ------------------- | ----------- | -------- | -------------------------------------------------------------------- |
| `:velero-inspect`   | `replay`    | none     | Render a saved Backup or Restore JSON object from this path.         |
| `:velero-trigger`   | `dry_run`   | `false`  | Show the velero command that would run and create no backup.         |
| `:velero-locations` | `namespace` | `velero` | The namespace the Velero installation lives in.                      |
| `:velero-locations` | `replay`    | none     | Render saved `kubectl get backupstoragelocations` JSON from a path.  |

```text
:velero-inspect replay=/absolute/path/to/backup.json
:velero-trigger dry_run=true
:velero-locations namespace=backup-system
```

Sofka runs adapters from the package directory, so a relative `replay` path does
not resolve from your shell directory. A replay file is read up to 1 MiB; a
larger file is an error. `:velero-trigger` has no `replay` input, because a
replayed trigger would report a backup that nothing created.

## Dependencies

Requires Sofka 0.27.4 or newer.

- `velero` on `PATH` for `:velero-trigger`, from
  https://velero.io/docs/main/basic-install/.
- `kubectl` on `PATH` for `:velero-locations`, from
  https://kubernetes.io/docs/tasks/tools/.
- `:velero-inspect` needs neither.

Both tools run with your credentials against the context sofka is showing; when
sofka has no explicit context, they use the kubeconfig's current one.

## How it is built

The adapter reads the request once and then borrows: every string the report
shows points into the request buffer or the tool output buffer, and the report
serializes straight into a buffered stdout rather than through an intermediate
value tree. Only a string carrying JSON escapes is copied, because unescaping
it needs bytes that are not in the buffer. A large backup object with hundreds
of items therefore costs one read and no per-field copies.

## Limitations

- `:velero-inspect` shows what Velero wrote to the object. It does not read the
  backup tarball, list the resources inside it, or check the object storage.
- Per-volume snapshot and item-operation detail is not reported; use
  `velero backup describe --details` for that.
- `:velero-trigger` does not wait for the backup, name it, or override the
  schedule's template.
- A tool that writes more than 1 MiB is an error; the adapter does not render a
  truncated report. Sofka refuses reports over 1 MiB in any case.
