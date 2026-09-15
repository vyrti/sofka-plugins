# deprecated-apis

Find Kubernetes apiVersions that are deprecated or already removed, before an
upgrade finds them for you. Two tools answer the same question, and this package
wraps both:

| Command            | Tool   | Scans                         | Changes the cluster |
| ------------------ | ------ | ----------------------------- | ------------------- |
| `:pluto-cluster`   | Pluto  | The whole context.            | No                  |
| `:kubent-cluster`  | kubent | The whole context.            | No                  |
| `:pluto-resource`  | Pluto  | The selected resource only.   | No                  |

The palette names say which tool runs, because that is what you choose between.
Install either tool, or both: each command names the one it needs, and a package
with one tool installed still gives you a working scan.

## What the report shows

Every finding becomes one line, in the same shape for both tools:

```text
apps/legacy-ingress — Ingress extensions/v1beta1 → networking.k8s.io/v1 (removed in v1.22.0)
```

The lines are grouped by what they cost you:

- **Removed with no replacement**: already gone, and there is no newer
  apiVersion to move to. These need a plan, not an edit.
- **Removed**: already gone in the target version. Change the apiVersion.
- **Deprecated**: still served, with the release that removes it named.

The **Summary** gives a verdict such as `3 removed, 1 deprecated`, the context,
the target versions the tool compared against, and the finding count. When
nothing is found the report says so instead of showing empty sections.

## Pluto and kubent

They disagree about detail, so the package keeps both rather than picking one.

- **Pluto** knows whether an apiVersion is merely deprecated or already removed
  at the target version, and names the release for each. It also checks
  components beyond Kubernetes itself, such as cert-manager and Istio.
- **kubent** reads Helm v3 release manifests as well as live objects, so it
  finds a deprecated apiVersion stored in a release that no live object uses
  any more. Every kubent rule set is about an apiVersion that some release
  removes, so its findings are all removals.

Run both when an upgrade is close. They do not always agree, and the difference
is usually a Helm release only kubent reads or a component only Pluto knows.

## Check selection for deprecations

`:pluto-resource` pipes the selected object into `pluto detect -` on standard
input. It works on any kind, because the check is on the apiVersion, which every
object carries. Nothing is sent to the cluster and nothing is written.

The object is forwarded as the exact bytes sofka sent, not re-serialized, so
Pluto sees what the API server returned.

Note that the API server returns the apiVersion it served the object as, not the
one it was created with. A Deployment created as `extensions/v1beta1` comes back
as `apps/v1`, so this command reports it as current. To find what is stored in a
Helm release, use `:kubent-cluster`.

## Exit codes

Pluto exits 2, 3 or 4 when it finds a deprecation, a removal, or a removal with
no replacement. That is a result, not a failure, so the adapter passes
`--ignore-deprecations`, `--ignore-removals` and
`--ignore-unavailable-replacements`. The exit code then says only whether Pluto
itself worked, and a real failure is still an error.

kubent exits 0 unless it is given `--exit-error`, which this package does not
pass.

## Live activity

The adapter sends scan phase messages to stderr for sofka's activity popup. It
forwards up to 64 KiB of tool diagnostics, then shows a truncation notice and
keeps draining. A failed activity write does not discard the report. Child read
and process failures remain errors.

kubent colours its progress log even when its output is not a terminal, so the
adapter runs it with `--log-level error`. Those escape codes would otherwise
land in the activity popup.

## Inputs

| Command            | Input            | Default | Purpose                                                          |
| ------------------ | ---------------- | ------- | ---------------------------------------------------------------- |
| `:pluto-cluster`   | `namespace`      | none    | Scan one namespace instead of the whole context.                 |
| `:pluto-cluster`   | `target_version` | none    | The Kubernetes version to compare against, such as `v1.31.0`.    |
| `:kubent-cluster`  | `target_version` | none    | The Kubernetes version to compare against, such as `1.31.0`.     |
| all three          | `report`         | none    | Render a saved tool report from this path instead of scanning.   |

```text
:pluto-cluster namespace=apps target_version=v1.31.0
:kubent-cluster target_version=1.31.0
```

Both tools detect the target version from the cluster when the input is empty.
Pluto wants a leading `v`, kubent does not; each input is passed to its own tool
unchanged.

Sofka runs adapters from the package directory, so a relative `report` path does
not resolve from your shell directory. A saved report is read up to 1 MiB; a
larger file is an error.

## Dependencies

Requires Sofka 0.27.4 or newer.

- `pluto` on `PATH` for `:pluto-cluster` and `:pluto-resource`, from
  https://pluto.docs.fairwinds.com/installation/.
- `kubent` on `PATH` for `:kubent-cluster`, from
  https://github.com/doitintl/kube-no-trouble#installation.

Both run with your credentials against the context sofka is showing; when sofka
has no explicit context, they use the kubeconfig's current one.

## How it is built

The adapter reads the request once and then borrows: every string the report
shows points into the request buffer or the tool output buffer, and the report
serializes straight into a buffered stdout rather than through an intermediate
value tree. Only a string carrying JSON escapes is copied, because unescaping it
needs bytes that are not in the buffer. A cluster with thousands of findings
therefore costs one read and no per-field copies.

Standard input for `:pluto-resource` is written on its own thread. Writing it
inline would deadlock as soon as the object outgrew the pipe buffer, because
nothing would be draining the tool's output meanwhile.

## Limitations

- The report is only as good as the tool's version data. An apiVersion removed
  after the tool's last release is not known to it; update the tool.
- `:pluto-resource` checks one object, as the API server serves it. See the
  note above about stored versus served apiVersions.
- Neither command rewrites anything. They tell you what to change.
- A tool that writes more than 1 MiB is an error; the adapter does not render a
  truncated report. Sofka refuses reports over 1 MiB in any case.
