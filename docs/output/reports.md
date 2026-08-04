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
  --report ./callweave-report.html
```

All generated-file paths in these examples are relative to the current working
directory, so the reports stay beside the command you ran instead of under
`/tmp`.

The report contains:

- aggregate chain count, average, P95, and maximum latency;
- three switchable views: a time-scaled cross-thread sequence, the existing
  causal waterfall, and detailed diagnostics/tables;
- a selectable causal waterfall whose rows preserve handoff order;
- queue, on-CPU, blocked, run-queue, and preempted/unknown composition;
- a per-hop comparison chart and raw correlation-key table;
- the longest futex wait and candidate waker for each asynchronous hop;
- final live queue diagnostics collected in BPF, including pending/running
  tasks, peak concurrency, averages, worker count, and a deterministic
  bottleneck assessment;
- exact per-hop latency distributions calculated from completed chains.

The same report surface also accepts standalone runtime modes:

```sh
sudo ./callweave -p PID --io-uring \
  --io-callback process_io_completion \
  --report ./callweave-io-uring.html

sudo ./callweave --epoll --duration 10 \
  --report ./callweave-epoll.html \
  --exec ./test/trace_epoll_test -- 100 --slow-callback --data-ptr

sudo ./callweave --libuv --duration 16 \
  --report ./callweave-libuv.html \
  --exec ./test/trace_libuv_test -- 8

sudo ./callweave --libevent --duration 12 \
  --report ./callweave-libevent.html \
  --exec ./test/trace_libevent_test -- \
  --startup-delay 0 --iterations 80 --lock-contention
```

Runtime reports normalize only evidence that the tracer actually observed:

- io_uring: SQE submission, kernel queue/in-flight phases, CQE completion, and
  the optional CQE-to-callback handoff; zero-duration queue phases are omitted;
- epoll: wait/ready followed by callback when configured, otherwise the first
  correlated I/O dispatch;
- libuv and libevent: wake or epoll-ready evidence followed by the automatically
  discovered native callback and its execution time.

The report retains at most 2,048 captured operations so a high-rate trace does
not create an unbounded browser document. Use the existing latency thresholds,
`--duration`, or `--max-events` to focus a long-running workload.

No JavaScript libraries, fonts, or network requests are required. Open the
generated file directly in a browser. In the Sequence view, time runs from top
to bottom: a high-contrast violet connector and filled wait band show queue time
between a source and its target thread, while a blue activation shows work time
in the target. Vertical order follows elapsed time, while phase spacing uses a
compressed scale so short waits and callbacks remain legible beside much longer
work. Exact durations remain attached to every phase. Scheduler-state colors within
the Waterfall work segment show aggregate composition; they do not claim that
those states occurred in that exact visual order.

epoll, libuv, and libevent reports use an event-loop-specific Sequence view
instead of the cross-thread layout. Conceptual role lanes separate epoll
readiness, the event loop, and callback or I/O execution even when they run on
the same TID. A gray phase is time blocked waiting for readiness, violet is an
observed wake-to-ready or ready-to-dispatch delay, and blue is callback or I/O
execution. This prevents an ordinary same-thread event-loop cycle from being
misrepresented as a pair of thread handoffs.


## JSON Lines

For automation or custom visualization, emit one completed asynchronous chain
per line as JSON:

```sh
sudo ./callweave -p 1234 \
  --config examples/thread-pool.yaml \
  --format json \
  --output trace.json \
  --report ./callweave-report.html
```

Without `--output`, JSON Lines are written to standard output and tracer status
is written to standard error. HTML `--report` supports async, epoll, libuv,
libevent, and io_uring modes. JSON Lines supports the same modes for automation.

Async output uses `type: "chain"` for completed chains and appends one
`type: "queue_diagnostics"` record on exit. Event-loop output uses
`epoll_callback` records plus an `epoll_summary`; runtime modes append their
own summary record. Automatically discovered libuv and libevent callbacks use
their ELF symbol when one is available (for example, `poll_callback` or
`bufferevent_read_callback`). If no usable symbol exists, the stable fallback
is `callback@0xADDRESS`. Explicit epoll and io_uring callback names remain as
configured. HTML lifecycle views combine the runtime role and implementation,
for example `libevent_callback (bufferevent_read_callback)`, while Callback
JSON includes the unwrapped resolved `callback` label, the raw
`callback_address`, and a nullable `futex` object with the
wait count, total wait time, longest wait, futex address, candidate waker, and
waker stack ID. Resource callback summaries retain aggregate futex totals and
the futex data from the invocation that established maximum callback duration.
