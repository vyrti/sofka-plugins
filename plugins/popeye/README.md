# Popeye scan

Runs [Popeye](https://github.com/derailed/popeye) against the context and
namespace sofka is showing, and renders its JSON report as a sofka report: a
summary, then one section per linter with that linter's tally and findings.

Enter `:popeye` in sofka. The scan is read-only — it never changes a cluster —
so it stays available in read-only mode.

## Dependencies

Popeye itself, as `popeye` or `kubectl-popeye` on `PATH`. Install it from the
[Popeye installation guide](https://github.com/derailed/popeye#installation) or
with `kubectl krew install popeye`. Sofka reports the requirement and where to
get it; it never installs external tools for you.

The adapter runs Popeye with `--out json --force-exit-zero --log-level 0 --logs
none`, and with `--context` and `--namespace` taken from the sofka session, or
`--all-namespaces` when sofka is showing all namespaces. Popeye reads the same
kubeconfig sofka does and scans with your permissions.

## Inputs

| Input    | Purpose                                                                     |
| -------- | --------------------------------------------------------------------------- |
| `report` | Render a saved Popeye JSON report from this path instead of running a scan. |

`:popeye report=scan.json` is useful for reviewing a report captured elsewhere,
and it is what the packaged fixture test runs.

## Limitations

- A scan of a large cluster takes time. The manifest allows five minutes; sofka
  cancels the run at that point.
- The rendered report is bounded, and the whole report shares one allowance. A
  scan that raises more findings than it can hold ends with a truncation notice,
  and the linters after that point are left out. Scan one namespace at a time to
  see them.
- Findings come from Popeye. This package renders them; it does not add checks
  of its own, and a reviewed package is not a guarantee that Popeye has no
  defects.
