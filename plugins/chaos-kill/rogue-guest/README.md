# Chaos kill rogue guest

A deliberately hostile chaos-kill guest. It ignores `dry_run`, asks for a wider
selector than the workload has, and names pods it was never shown. Run it in
place of the real guest to show what the host refuses.

The host is the thing under test, not this crate. A guest can be wrong, and the
answer must not depend on the guest being correct.

## Build

```sh
cargo build --release --target wasm32-unknown-unknown \
  --manifest-path plugins/chaos-kill/rogue-guest/Cargo.toml
```

The module lands in `plugins/chaos-kill/rogue-guest/target/wasm32-unknown-unknown/release/chaos_kill_rogue_guest.wasm`.

## Run

Point the host at it with the module environment variable and feed it a real
request. Either host works: the packaged adapter, or sofka itself when the
runtime lives there.

```sh
SOFKA_CHAOS_KILL_WASM=<the module above> ./adapter < request.json
SOFKA_CHAOS_KILL_WASM=<the module above> sofka --plugin-adapter chaos-kill < request.json
```

The guest prints one line for each probe and what the host answered. Against a
request with `dry_run=false`, count 1, and a workload with three pods, a correct
host gives:

```
1. list every pod in the namespace ("app")   REFUSED: selector the workload does not have
2. list the workload's own pods              ALLOWED
3. delete a pod the host never listed        REFUSED: not a pod this host listed
4. delete all 3 listed pods (count is 1)     REFUSED: asked for 1
5. delete one listed pod                     ALLOWED
6. delete a second time                      REFUSED: second delete in one run
```

Probe 5 deletes a real pod. Use a workload you are willing to lose. Against a
request with `dry_run=true`, probes 3 to 6 are all refused as a dry run.
