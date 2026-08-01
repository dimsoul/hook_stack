<!-- SPDX-License-Identifier: MIT -->

# callweave-ebpf

`callweave` is a no-instrumentation asynchronous latency debugger for native Linux applications. It uses eBPF and uprobes to connect selected user-space functions, thread handoffs, scheduler delays, epoll readiness, io_uring completions, and runtime callbacks into evidence-backed causal paths.

It is designed to answer questions such as:

- Who submitted this work?
- How long did it wait before another thread started it?
- Was the target executing, blocked, or waiting for CPU?
- Which epoll-ready FD or io_uring request led to the slow work?
- Did a libuv callback actually run, or is only a weaker fallback correlation available?

Callweave complements sampling profilers and distributed tracing. A profiler shows where CPU samples accumulate, while Callweave focuses on selected asynchronous operations and explains where their elapsed time went.

## What it can trace

| Area | Main result | Documentation |
| --- | --- | --- |
| Native functions | Entry stack, return value, duration, scheduler-state attribution, and futex waker | [Function tracing](docs/features/function-tracing.md) |
| Cross-thread work | Up to eight handoffs with queue and work latency for every hop | [Async call chains](docs/features/async-call-chain.md) |
| Thread pools | Pending and active work, worker observations, tail latency, and deterministic bottleneck hints | [Queue diagnostics](docs/features/queue-diagnostics.md) |
| epoll | Wait batches, ready-to-I/O dispatch, FD lifetime, wake sources, callback timing, ET/ONESHOT diagnostics, and waiter fairness | [epoll diagnostics](docs/features/epoll.md) |
| io_uring | SQE-to-CQE latency, io-wq behavior, ring pressure, errors, linked requests, resources, and optional user callback correlation | [io_uring diagnostics](docs/features/io-uring.md) |
| libuv | Automatic native `uv_poll_t` handle, FD, and callback discovery over the epoll tracer | [libuv adapter](docs/runtimes/libuv.md) |

## Causal model

For an asynchronous thread-pool path, Callweave reconstructs:

```text
producer stack
    -> source function
    -> queue wait
    -> target thread starts
    -> target work: on-CPU / blocked / run queue / preempted
    -> next handoff or final return
```

For an event-loop path, it connects:

```text
wake source
    -> monitored FD becomes ready
    -> epoll returns
    -> ready-to-I/O dispatch
    -> runtime callback entry and return
```

Every resolvable epoll path is classified by its strongest observed evidence:

- `exact`: readiness plus a completed matched callback;
- `ready-to-I/O`: callback boundary unavailable, but matching FD I/O observed;
- `ready-only`: readiness observed without a matching callback completion or I/O.

See [evidence levels](docs/reference/evidence-levels.md) for the exact semantics.

## Requirements

- Linux 5.8 or newer as a practical baseline.
- Kernel BTF at `/sys/kernel/btf/vmlinux`.
- `clang`, `llvm`, `bpftool`, `make`, and `addr2line`.
- Development packages for libbpf, libelf, and zlib.
- Root or sufficient BPF/perf capabilities.

On Debian or Ubuntu:

```sh
sudo apt install make clang llvm bpftool binutils libbpf-dev libelf-dev zlib1g-dev
```

The libuv adapter does not link Callweave against libuv. Only the optional test program needs `libuv1-dev`:

```sh
sudo apt install libuv1-dev
```

See [getting started](docs/getting-started.md) for build artifacts and source layout.

## Build

```sh
make
```

The build generates `src/vmlinux.h`, the BPF object, the libbpf skeleton, the `callweave` executable, and bundled test programs.

## Quick start

Trace a function in an existing process:

```sh
sudo ./callweave -p PID function_to_trace
```

Measure its return value, duration, and scheduler-state attribution:

```sh
sudo ./callweave -p PID --ret --attribution function_to_trace
```

Trace a two-hop asynchronous chain:

```sh
sudo ./callweave -p PID \
  --async-hop submit_compute_task,2,process_request,1 \
  --async-hop submit_storage_task,2,write_result,1 \
  write_result
```

Load the same trace from a configuration file:

```sh
sudo ./callweave -p PID --config examples/thread-pool.yaml
```

Diagnose io_uring requests:

```sh
sudo ./callweave -p PID --io-uring
```

Diagnose an epoll event loop:

```sh
sudo ./callweave -p PID --epoll
```

Automatically adapt native libuv poll callbacks:

```sh
sudo ./callweave -p PID --libuv
```

To avoid missing initialization, let Callweave launch an epoll or libuv target after all probes are ready:

```sh
sudo ./callweave --libuv --duration 20 \
  --exec ./server -- --port 8080
```

## Output detail modes

epoll and libuv default to a final aggregate summary:

```sh
sudo ./callweave -p PID --libuv
```

Stream only slow or anomalous paths:

```sh
sudo ./callweave -p PID --libuv --live
```

Stream every collected detail:

```sh
sudo ./callweave -p PID --libuv --verbose
```

The advanced `--min-epoll-*-us` options remain available for custom BPF-side thresholds. See the [CLI reference](docs/reference/cli-options.md).

## Reports

Completed asynchronous chains can be exported as JSON Lines and as a self-contained HTML report:

```sh
sudo ./callweave -p PID \
  --config examples/thread-pool.yaml \
  --format json \
  --output /tmp/callweave.jsonl \
  --report /tmp/callweave.html
```

Standalone epoll, libuv, and io_uring modes also provide structured JSON summaries. See [JSON and HTML output](docs/output/reports.md).

## Documentation

Start with the [documentation index](docs/README.md).

- [Getting started](docs/getting-started.md)
- [CLI reference](docs/reference/cli-options.md)
- [Function tracing](docs/features/function-tracing.md)
- [Asynchronous call chains](docs/features/async-call-chain.md)
- [Queue and thread-pool diagnostics](docs/features/queue-diagnostics.md)
- [epoll diagnostics](docs/features/epoll.md)
- [io_uring diagnostics](docs/features/io-uring.md)
- [libuv adapter](docs/runtimes/libuv.md)
- [Evidence levels](docs/reference/evidence-levels.md)
- [Testing guide](docs/testing.md)
- [Troubleshooting](docs/troubleshooting/common-issues.md)
- [Architecture](docs/architecture.md)

## Why not use GDB?

GDB is the better tool for stopping at one failure, inspecting complex variables, and stepping through control flow. It can also script cross-thread correlation, but breakpoints stop threads and can perturb the scheduling and queueing behavior being investigated.

Callweave is intended for short, targeted observation when stopping the process would change the result. It records events with eBPF instead of pausing on every hit, but uprobes, stack collection, and symbolization still have overhead. Very hot functions should be selected carefully.

## Scope and boundaries

- Correlation keys are raw nonzero integer or pointer values; Callweave does not infer application types.
- Automatic target-argument scanning accepts a match only when exactly one of arguments 1-8 matches.
- Kernel and runtime tracepoint availability varies by version; optional capabilities degrade with warnings.
- Late attachment cannot reconstruct activity that completed before probes were active.
- Runtime adapters only claim `exact` evidence when a complete matching callback entry/return pair was observed.
- This is a targeted diagnostic tool, not an always-on high-cardinality tracing backend.

Run `./callweave --help` for the current complete option list.
