<!-- SPDX-License-Identifier: MIT -->

# io_uring diagnostics

[Documentation index](../README.md) · [Project README](../../README.md)


Use the standalone `--io-uring` mode when the slow operation is submitted
through an io_uring rather than a known user-space function:

```sh
sudo ./callweave -p PID --io-uring
sudo ./callweave -p PID --io-uring --duration 10 --max-events 100
```

This mode does not require a binary path or function name. It correlates the
kernel's `io_uring_submit_req` and `io_uring_complete` tracepoints by the
kernel request pointer, then reports:

- SQE opcode and file descriptor when available;
- the application-defined `user_data` copied into the CQE;
- CQE result and flags;
- submission-to-completion latency;
- execution-path attribution for deferred requests, poll arming, and io-wq,
  including io-wq queue time and worker-start-to-CQE time when the running
  kernel exposes the corresponding tracepoints;
- the submitting thread's user stack;
- final submitted, completed, pending, peak-pending, unmatched, and dropped
  counters, plus per-opcode average and maximum latency;
- total errors, error rate, expected timeout count, per-opcode error rate, and
  the most frequent errno values. A `TIMEOUT` request completed with `-ETIME`
  is reported as an expected timeout rather than a failed request;
- per-ring setup flags, SQ/CQ sizes, pending depth, CQ waits and overflows,
  registered resources, io-wq pressure, and a short diagnosis;
- sampled invalid-SQE fields from `io_uring_req_failed` and linked-request
  parent/child relationships;
- the path behind a file descriptor, snapshotted while the target is alive.
  Socket descriptors are enriched with TCP/UDP or Unix-socket endpoints when
  `/proc/PID/net` exposes them.

Some of the diagnostic tracepoints are kernel-version dependent. Missing
optional probes are reported as warnings; the core submit-to-CQE tracer remains
usable.

When `-p PID` is used, callweave monitors that process with `pidfd` and exits
automatically after the target exits. `Ctrl+C`, `--duration`, and
`--max-events` can still stop an active trace earlier.

The first `Ctrl+C` stops collection and prints the final summary. During that
summary, callweave symbolizes each unique Top-N submit stack once and reuses
the result for groups with the same stack ID. Press `Ctrl+C` a second time to
cancel any in-progress symbolization and exit immediately.

For high-rate applications, keep aggregate counters for every completion but
only emit detailed slow or failed requests:

```sh
sudo ./callweave -p PID --io-uring \
  --min-io-latency-us 1000 \
  --io-top 20

sudo ./callweave -p PID --io-uring \
  --io-errors-only \
  --io-top 20
```

The latency threshold is applied in BPF before reserving a ring-buffer event,
so filtered requests do not trigger per-event output or symbolization.
`--io-top N` reports the N groups with the largest maximum latency, grouped by
opcode, file descriptor, and submit stack. When the threshold and
`--io-errors-only` are combined, a detailed event must satisfy both filters.
The final error summary is computed from BPF-side counters and result
aggregates, so it still includes requests omitted by those detail filters.

The terminal summary is separated into numbered sections: capture overview,
operation latency, application errors, ring/queue health, linked requests,
slowest submit groups, and collector health. Kernel-rejected SQEs are reported
under application errors; unmatched correlations and dropped ring-buffer
events are kept in the final collector-health section so the two categories
are not confused.

## CQE to user callback

The kernel does not execute the application callback: user space reads a CQE
from shared memory and then decides what function to call. When that callback
is known, callweave can extend the chain beyond the CQE:

```sh
sudo ./callweave -p PID --io-uring \
  --io-callback process_io_completion \
  --io-callback-arg 1
```

`--io-callback-arg N` identifies the callback argument whose scalar value is
the CQE `user_data` value; it defaults to argument 1 and accepts 1-8.
`--io-callback-binary PATH` selects a shared library or another ELF instead of
the default `/proc/PID/exe`. A successful match reports CQE-to-callback
latency, callback thread, and callback user stack. The final callback counters
also expose matched, unmatched, and dropped events.

This adapter compares values, not memory addresses. It works when the callback
receives `user_data` directly. If a runtime passes a wrapper object or CQE
pointer instead, a runtime-specific adapter is needed to extract the value;
choosing an arbitrary argument would otherwise create misleading matches.

`user_data` is displayed as application context; it is not used as the unique
correlation key because applications may reuse it. Multishot requests remain
pending while `IORING_CQE_F_MORE` is set. With `IORING_SETUP_SQPOLL`, the
kernel submission tracepoint can run in the polling thread, so callweave uses
the request's owning task for PID filtering but cannot collect that original
task's user stack at that later point.

JSON Lines output is available for automation:

```sh
sudo ./callweave -p PID --io-uring --format json \
  --output /tmp/callweave-io-uring.jsonl
```

Each completion is an `io_uring` record. With `--io-callback`, matches are
additional `io_uring_callback` records. The final `io_uring_summary` includes
per-operation aggregates, error codes, Top-N groups, ring diagnostics, invalid
SQE samples, and linked-request edges. The asynchronous-chain HTML report
currently has a different data model and is therefore not accepted in this
mode.
