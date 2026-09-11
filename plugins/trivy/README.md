# Trivy scan

Runs [Trivy](https://trivy.dev) against the context and namespace sofka is
showing, and renders its Kubernetes report as a sofka report: a summary of
findings by severity, then one section per affected resource listing its
vulnerabilities, misconfigurations, and secrets.

Enter `:trivy` in sofka. The scan is read-only — it never changes a cluster —
so it stays available in read-only mode.

## Dependencies

Trivy itself, as `trivy` on `PATH`. See the
[Trivy installation guide](https://trivy.dev/latest/getting-started/installation/).
Sofka reports the requirement and where to get it; it never installs external
tools for you.

The adapter runs `trivy kubernetes --format json --report summary`, with
telemetry, the version check, the progress bar, and the node collector turned
off, `--include-namespaces` set from the sofka session, and the kubeconfig
context as the positional argument. Trivy reads the same kubeconfig sofka does
and scans with your permissions.

## Inputs

| Input    | Purpose                                                                    |
| -------- | -------------------------------------------------------------------------- |
| `report` | Render a saved Trivy JSON report from this path instead of running a scan. |

`:trivy report=scan.json` is useful for reviewing a report captured elsewhere,
and it is what the packaged fixture test runs.

## Limitations

- A cluster-wide scan pulls and inspects every image it finds. It takes time and
  bandwidth, and the manifest allows five minutes before sofka cancels the run.
  Narrow it with a namespace.
- Resources with no findings are left out. A cluster-wide scan touches every
  workload, and listing the clean ones would bury the findings.
- The rendered report is bounded, and the whole report shares one allowance. A
  scan with more findings than it can hold ends with a truncation notice, and
  the resources after that point are left out. Scan one namespace at a time to
  see them.
- Findings come from Trivy. This package renders them; it does not add checks of
  its own, and a reviewed package is not a guarantee that Trivy has no defects.

Responsible maintainer: `@vyrti`.
