<!-- SPDX-License-Identifier: MIT -->

# Queue and thread-pool diagnostics

[Documentation index](../README.md) · [Project README](../../README.md)


Async tracing maintains one real-time statistics record for every configured
hop. The source probe increments `submitted` and `pending`; matching target
entry decrements `pending`, increments `started` and `active`, and records queue
latency; completion decrements `active`, increments `completed`, and records
work latency. Intermediate-hop work ends at the next handoff, matching the
causal-chain timing model. Final-hop work ends when the traced target returns.

By default, a queue snapshot is printed every second and once more when
callweave exits:

```sh
sudo ./callweave -p PID --config examples/complex-multi-hop.yaml \
  --diagnostic-interval-ms 1000
```

Set the interval to `0` to suppress periodic snapshots while retaining the
final JSON/HTML diagnostic:

```sh
sudo ./callweave -p PID --config examples/complex-multi-hop.yaml \
  --diagnostic-interval-ms 0 \
  --report ./callweave-report.html
```

Each stage reports:

- submit/start/complete rates;
- current and peak pending tasks;
- current and peak active target invocations;
- exact accumulated average queue and work latency;
- observed worker-thread count and the busiest worker;
- futex-wait ratio, duplicate correlation keys, expired contexts, unmatched
  targets, and targets that returned without handing off the next hop.

The diagnosis is rule-based and reproducible: growing pending work indicates
backlog, pending work while workers are active indicates saturation, and a high
futex-wait ratio indicates lock contention. It does not require AI.

The BPF side deliberately does not maintain latency histograms. The HTML report
groups the exact `queue_ns` and `work_ns` values already carried by completed
chains, sorts them in the browser, and calculates per-hop average, P50, P95,
P99, and maximum latency. P95 is hidden below 20 completed samples and P99 is
hidden below 100, so small test runs do not present an unstable tail percentile
as a reliable result. Queue-versus-work observations are also withheld until
at least 20 completed samples are available.

The live counters include work that is still queued or running, unlike the
completed-chain charts. `pending` is observational rather than an application
queue's authoritative length: LRU eviction, process exit, dropped probes, or
reused correlation keys can leave it approximate. The anomaly counters make
those conditions visible.
