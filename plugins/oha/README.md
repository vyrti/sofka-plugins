# HTTP benchmark

Sends HTTP load at the selected pod or service with [oha](https://github.com/hatoo/oha)
and renders the result: throughput, latency percentiles, status codes, and
errors.

Select a pod or service and enter `:oha`. Sofka asks for confirmation first,
every time.

## This one generates traffic

Every other package in this catalog only reads. This one puts a workload under
sustained load, so its manifest sets `network_load = true`. Sofka treats that
as it would a destructive action: it confirms before each run, marks the
confirmation dialog, and refuses entirely in read-only mode. Point it at
production only when you mean to.

The manifest caps the run at five minutes and the `duration` input at 300
seconds, so a mistyped argument cannot leave load running.

## How it reaches the workload

Sofka opens a `kubectl port-forward` to the port you name, waits for it to
answer, and tells the adapter which local port to use. The adapter never shells
out to kubectl and never guesses whether a cluster address is routable from
your machine. An existing saved forward for the same target and port is reused
rather than duplicated, and the forward is closed when the run ends.

## Dependencies

oha itself, on `PATH`. See the
[oha installation guide](https://github.com/hatoo/oha#installation). Sofka
reports the requirement and where to get it; it never installs external tools
for you.

## Inputs

| Input         | Default | Purpose                                   |
| ------------- | ------- | ----------------------------------------- |
| `port`        | `80`    | Remote port to forward and benchmark.     |
| `duration`    | `10s`   | How long to send load, up to 300 seconds. |
| `connections` | `20`    | Concurrent connections.                   |
| `path`        | `/`     | Request path.                             |

`:oha port=8080 duration=30s connections=50 path=/healthz`

## Limitations

- HTTP only, one URL, no request body or custom headers.
- The report is oha's. This package renders it; it adds no measurement of its
  own, and a reviewed package is not a guarantee that oha has no defects.
- A run that completes no requests still reports, because its error counts are
  usually what explains the failure.
