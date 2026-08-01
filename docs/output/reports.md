<!-- SPDX-License-Identifier: MIT -->

# JSON and HTML output

[Documentation index](../README.md) · [Project README](../../README.md)

## Self-contained HTML report

Generate an interactive, self-contained HTML report while retaining the normal
terminal output:

```sh
sudo ./callweave -p 1234 \
  --config examples/thread-pool.yaml \
  --max-events 100 \
  --report callweave-report.html
```

The report contains:

- aggregate chain count, average, P95, and maximum latency;
- a selectable causal waterfall whose rows preserve handoff order;
- queue, on-CPU, blocked, run-queue, and preempted/unknown composition;
- a per-hop comparison chart and raw correlation-key table;
- the longest futex wait and candidate waker for each asynchronous hop;
- final live queue diagnostics collected in BPF, including pending/running
  tasks, peak concurrency, averages, worker count, and a deterministic
  bottleneck assessment;
- exact per-hop latency distributions calculated from completed chains.

No JavaScript libraries, fonts, or network requests are required. Open the
generated file directly in a browser. Scheduler-state colors within a work
segment show aggregate composition; they do not claim that those states
occurred in that exact visual order.


## JSON Lines

For automation or custom visualization, emit one completed asynchronous chain
per line as JSON:

```sh
sudo ./callweave -p 1234 \
  --config examples/thread-pool.yaml \
  --format json \
  --output trace.json \
  --report callweave-report.html
```

Without `--output`, JSON Lines are written to standard output and tracer status
is written to standard error. `--format json` and `--report` currently require
an async trace because their data model is a completed causal chain. Existing
slow-chain filters are applied before either export is written.
JSON Lines output uses `type: "chain"` for completed chains and appends one
`type: "queue_diagnostics"` record on exit.
