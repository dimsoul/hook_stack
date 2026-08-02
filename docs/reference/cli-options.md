<!-- SPDX-License-Identifier: MIT -->

# CLI reference

[Documentation index](../README.md) · [Project README](../../README.md)

The executable is the authoritative source for the complete option list:

```sh
./callweave --help
```

## Primary command forms

```text
./callweave [OPTIONS] BINARY FUNCTION
./callweave -p PID [--module MODULE] FUNCTION
./callweave --binary BINARY --offset OFFSET
./callweave -p PID --config PATH
./callweave -p PID --io-uring
./callweave -p PID --epoll
./callweave -p PID --libuv
./callweave -p PID --libevent
./callweave --epoll --exec PROGRAM -- [ARGS...]
./callweave --libuv --exec PROGRAM -- [ARGS...]
./callweave --libevent --exec PROGRAM -- [ARGS...]
```

## Output detail modes

The epoll, libuv, and libevent modes default to the final aggregate summary.

| Option | Behavior |
| --- | --- |
| `--summary-only` | Explicitly select the default final-summary behavior. |
| `--live` | Stream slow callbacks, slow dispatches, and anomalous paths. |
| `--verbose` | Stream every collected wait, dispatch, and callback detail. |

The advanced `--min-epoll-wait-us`, `--min-epoll-dispatch-us`, and `--min-epoll-callback-us` options select custom BPF-side thresholds. Do not combine explicit thresholds with the three preset output modes.

## Function tracing

- `--ret`: print the raw return register.
- `--time`: measure function entry-to-return latency.
- `--attribution`: add on-CPU, blocked, run-queue, and preempted/unknown attribution; implies `--time`.
- `--module MODULE`: select an already mapped shared object for a PID.
- `--offset OFFSET`: attach at a known ELF file offset.
- `--find-symbol SYMBOL`: search mapped ELF modules without attaching.

See [function tracing](../features/function-tracing.md).

## Asynchronous chains

- `--async-hop SOURCE,SOURCE_ARG,TARGET[,TARGET_ARG]`: add one handoff, up to eight.
- `--config PATH`: load a repeatable multi-hop configuration.
- `--discover-async FUNCTION`: inspect the most recent scheduler waker for a target.
- `--min-total-ms`, `--min-queue-ms`, `--min-work-ms`: retain slow chains.
- `--diagnostic-interval-ms`: control live queue snapshots.

See [asynchronous call chains](../features/async-call-chain.md) and [queue diagnostics](../features/queue-diagnostics.md).

## Standalone diagnostic modes

- `--io-uring`: SQE-to-CQE lifecycle, ring health, errors, and io-wq behavior.
- `--epoll`: wait batches, ready-to-I/O dispatch, FD lifetime, wake sources, and event-loop health.
- `--libuv`: epoll diagnostics plus automatic native `uv_poll_t` callback discovery.
- `--libevent`: epoll diagnostics plus automatic libevent event/FD/callback discovery.
- `--libuv-binary PATH`, `--libevent-binary PATH`: override runtime-library auto-detection for unusual loader layouts or later `dlopen`.

See [io_uring](../features/io-uring.md), [epoll](../features/epoll.md), [libuv](../runtimes/libuv.md), and [libevent](../runtimes/libevent.md).

## Capture and export controls

- `--duration SEC`: stop after a fixed duration.
- `--max-events N`: stop after matching detailed events or chains.
- `--format text|json`: select terminal text or JSON Lines.
- `--output PATH`: write JSON Lines to a file.
- `--report PATH`: write the asynchronous-chain HTML report.
