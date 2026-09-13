# Popeye scan

Runs [Popeye](https://github.com/derailed/popeye) against the context and
namespace sofka is showing. A WebAssembly guest renders its JSON output as a
sofka report with a summary and one section for each linter.

Enter `:popeye` in sofka. The scan is read-only. It never changes a cluster, so
it stays available in read-only mode.

## Runtime

The native `adapter` runs the guest with Wasmi 2.0.0. The guest can request two
host operations: read a saved report or run Popeye for the supplied context and
namespace. It cannot select another executable or supply arbitrary arguments.
The host limits guest memory to 128 MiB and limits source reports to 32 MiB.

The release package contains `adapter` and `popeye.wasm`. For a local release
build, install the `wasm32-unknown-unknown` Rust target and `wasm-opt`, then run:

```sh
scripts/build-popeye-wasm.sh target/release/popeye.wasm
cargo build --release --locked --package sofka-plugin-popeye
```

## Dependencies

Popeye itself, as `popeye` on `PATH`. Install it from the
[Popeye installation guide](https://github.com/derailed/popeye#installation).
Sofka reports the requirement and where to get it; it never installs external
tools for you.

The adapter runs Popeye with `--out json --force-exit-zero --log-level 0 --logs
none`, and with `--context` and `--namespace` taken from the sofka session, or
`--all-namespaces` when sofka is showing all namespaces. Popeye reads the same
kubeconfig sofka does and scans with your permissions.

## Inputs

| Input    | Purpose                                                                     |
| -------- | --------------------------------------------------------------------------- |
| `report` | Render a saved Popeye JSON report from this path instead of running a scan. |

`:popeye report=/absolute/path/to/scan.json` is useful for reviewing a report
captured elsewhere. Sofka runs adapters from the package directory, so relative
paths do not resolve from the shell directory. The packaged fixture test uses
the same replay path internally; its `fixtures/scan.json` is an unedited
`popeye --out json` capture, so the field names it asserts are the ones Popeye
emits.

## Limitations

- A scan of a large cluster takes time. The manifest allows five minutes; sofka
  cancels the run at that point.
- The rendered report is bounded, and the whole report shares one allowance. A
  scan that raises more findings than it can hold ends with a truncation notice,
  and the linters after that point are left out. For an all-namespace scan,
  retry one namespace at a time; otherwise inspect the full Popeye JSON output.
- Findings come from Popeye. This package renders them; it does not add checks
  of its own, and a reviewed package is not a guarantee that Popeye has no
  defects.
