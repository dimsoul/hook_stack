<!-- SPDX-License-Identifier: MIT -->

# callweave-ebpf

`callweave` is a no-instrumentation, function-level asynchronous latency
debugger for native Linux applications. It follows a request across thread
pools and private task queues, then shows where each hop queued, ran, blocked,
or waited for CPU.

Unlike a sampling profiler or protocol-level distributed tracer, `callweave`
targets selected ELF functions and correlates handoffs with an application
pointer or request ID. It can answer "who submitted this work, how long did it
wait, and why was each processing stage slow?" without rebuilding or modifying
the target application.

## Features

- Attach to a function by ELF symbol name.
- Trace every process using the ELF, or restrict tracing to one PID.
- Capture up to 128 user-space frames per call.
- Resolve PIE executables and shared-library frames against their actual ELF
  mappings.
- Translate kernel-global process IDs into the tracer's PID namespace, so
  symbolization works inside containers and PID namespaces.
- Batch addresses by module before invoking `addr2line`.
- Report PID, TID, process name, raw instruction pointer, module, function, and
  source location.
- Optionally attach a return probe to report the raw return register value and
  function execution time.
- Attribute latency to on-CPU, blocked, run-queue, and preempted/unknown time.
- Identify the longest futex wait, its address, and the matching wake caller
  thread and user stack.
- Stitch a producer stack to a target running in another thread by matching a
  shared task pointer or request ID.
- Discover the thread and user stack that most recently woke a target thread,
  then suggest a candidate source function for async tracing.
- Retain up to eight asynchronous handoffs and report queue time, target work
  time, scheduler-state attribution, and the dominant delay class for each hop.
- Load repeatable multi-hop traces from a small YAML configuration file.
- Keep only slow chains by total, queue, or work time, and stop after a chosen
  event count or duration.
- Export completed chains as JSON Lines or a self-contained HTML report with a
  causal waterfall, per-hop scheduler breakdown, and aggregate latency cards.
- Diagnose live queue backlog and thread-pool saturation with per-hop BPF
  counters, exact accumulated averages, worker observations, and deterministic
  hints.
- Correlate io_uring SQE submission with CQE completion and diagnose ring,
  io-wq, error, and resource behavior.
- Diagnose epoll event loops by wait batch, ready-to-I/O dispatch latency,
  ready-to-next-wait scheduler attribution, FD lifetime, ONESHOT rearm,
  multi-waiter fairness, timeout/error behavior, full-batch pressure,
  EPOLLET drain evidence, call site, monitored resources, and eventfd,
  timerfd, and signalfd wake-source attribution.
- Correlate an epoll-ready FD with a selected user callback and report
  ready-to-callback delay, callback duration, scheduler-state attribution,
  slowest call sites, and nested callback execution.
- Automatically adapt native libuv `uv_poll_t` watchers by learning their
  handle, FD, event mask, and callback from the public libuv API, without
  requiring callback names or argument positions.
- Pair nested and recursive calls independently for each thread.
- Stop cleanly on `SIGINT` or `SIGTERM`.

## Why not use GDB?

GDB can reproduce the basic workflow in a development environment. Breakpoints
and a GDB Python script can read arguments, capture backtraces, associate a
request pointer or ID across threads, and measure the wall-clock interval
between source and target functions. GDB remains the better choice when the
main goal is to stop at one failure, inspect complex variables, or step through
control flow.

The trade-off is that software breakpoints use `ptrace` and stop a thread when
they fire. GDB's non-stop mode can reduce process-wide pauses, but frequent
breakpoints still perturb scheduling, queueing, and latency. Reconstructing a
multi-hop lineage also requires custom scripting and lifecycle management for
every saved request key.

`callweave` is intended for a different diagnostic mode:

| Question | GDB | `callweave` |
| --- | --- | --- |
| Inspect complex variables and memory | Strong | Raw integer or pointer keys only |
| Capture a function's caller stack | Built in | Built in |
| Correlate a request across threads | Custom breakpoint script | Repeated `--async-hop` options |
| Follow multiple asynchronous handoffs | Custom state management | Up to eight retained hops |
| Separate queue time from target work | Scripted timestamps | Reported for every hop |
| Split work into on-CPU, blocked, and run-queue time | Not a native breakpoint capability | Derived from scheduler tracepoints |
| Effect on a frequently hit target | Threads stop on every breakpoint | No debugger stop; events are recorded by eBPF |

This does not make `callweave` a replacement for GDB. Use GDB for interactive
correctness debugging and detailed state inspection. Use `callweave` for
short, targeted observation of a running native process when stopping it would
change the queueing or scheduling behavior being investigated. Uprobes, stack
collection, and symbolization still have overhead, so very hot functions
should be traced selectively.

## Requirements

- Linux with BPF, BTF, ring-buffer, and uprobe support. Linux 5.8 or newer is a
  practical baseline because this project uses `BPF_MAP_TYPE_RINGBUF`.
- A readable kernel BTF file at `/sys/kernel/btf/vmlinux`.
- `clang`, `llvm`, `bpftool`, `make`, and `addr2line` (usually from binutils).
- Development packages for `libbpf`, `libelf`, and zlib.
- Root or sufficient BPF/perf capabilities to load BPF programs and attach
  uprobes.

For Debian or Ubuntu, the dependencies are typically installed with:

```sh
sudo apt install make clang llvm bpftool binutils libbpf-dev libelf-dev zlib1g-dev
```

Neither epoll nor libuv is a Callweave runtime dependency. epoll is a Linux
kernel API, while the libuv adapter observes the copy already used by the
target process and does not link Callweave with `-luv`. Only the optional
libuv example requires the development package:

```sh
sudo apt install libuv1-dev
make test-libuv
```

## Build

Run the build from the repository root:

```sh
make
```

The Makefile generates the following build artifacts automatically:

1. `src/vmlinux.h` from the running kernel's BTF data.
2. `src/callweave.bpf.o`, compiled for the current architecture.
3. `src/callweave.skel.h`, generated by `bpftool`.
4. The `callweave` loader and the example programs under `test/`.

Set tool variables when the defaults are not appropriate, for example:

```sh
make CLANG=clang-18 BPFTOOL=/usr/sbin/bpftool
```

### Source layout

The implementation is split by responsibility so changes to one tracer mode
do not require editing a single monolithic loader:

- `src/callweave.c`: command-line handling, probe attachment, and lifecycle.
- `src/core/`: target-selection and core function-tracing configuration,
  capture lifecycle, signal state machine, and shared FD resource resolution.
- `src/async/`: async-chain configuration, event ABI, filtering, queue
  diagnostics, and event rendering.
- `src/config.c`: YAML-like trace configuration and option value parsing.
- `src/symbols.c`: process maps, ELF symbol lookup, and `addr2line` resolution.
- `src/io_uring/`: the complete io_uring feature module. Its event handling,
  configuration, event handling, aggregation/reporting, resource resolution,
  shared ABI, BPF maps, and BPF probes live together so future runtime
  integrations can use parallel directories.
- `src/epoll/`: epoll syscall correlation, existing-registration discovery,
  event-loop/resource aggregation, rendering, and BPF programs.
- `src/libuv/`: native `uv_poll_t` API observation, handle-to-FD state, and
  dynamic attachment to callbacks discovered at runtime.
- `src/report.c`: async JSON Lines and self-contained HTML reports.
- `src/callweave.bpf.c`: common eBPF probes and async tracing.
- `src/async/async_events.h` and `src/io_uring/io_uring_shared.h`:
  kernel/userspace event layouts. Generated `src/vmlinux.h` and
  `src/callweave.skel.h` remain build artifacts.

## Usage

```text
Usage:
  ./callweave [OPTIONS] BINARY FUNCTION
  ./callweave -p PID [--module MODULE] FUNCTION
  ./callweave -p PID [--module MODULE] --find-symbol SYMBOL
  ./callweave --binary BINARY --offset OFFSET
  ./callweave -p PID --discover-async FUNCTION
  ./callweave -p PID --config PATH
  ./callweave -p PID --io-uring
  ./callweave -p PID --epoll
  ./callweave -p PID --libuv
  ./callweave --libuv --exec PROGRAM -- [ARGS...]
  ./callweave --check-config PATH
```

Add `--ret` to report the raw return register value and `--time` to report the
time from function entry to return:

```sh
sudo ./callweave -p 1234 --ret --time function_name
sudo ./callweave -p 1234 --module libc.so.6 --ret --time malloc
sudo ./callweave --binary ./program --offset 0x11c9 --ret --time
```

`--return-value` is an alias for `--ret`, and `--latency` is an alias for
`--time`. Return tracing is disabled unless at least one of these options is
present, so the original entry-only mode has no return-probe bookkeeping.
Event prefixes include microseconds, for example
`[2026-07-27 10:28:26.123456]`. The timestamp is captured when the BPF event is
created and converted from the kernel monotonic clock to local wall time; it
is not the later time at which userspace happens to drain the ring buffer.

Break function latency down by scheduler state:

```sh
sudo ./callweave -p 1234 --attribution function_name
```

`--attribution` (alias `--breakdown`) implies `--time`. A return event then
contains fields similar to:

```text
RETURN duration=20.112 ms oncpu=83.421 us offcpu=20.029 ms blocked=20.011 ms runq=18.327 us preempt/unknown=0 ns
```

The fields mean:

- `oncpu`: time during which the traced thread was running, derived as total
  duration minus off-CPU time;
- `blocked`: time from a scheduler switch-out until an observed wakeup,
  including waits caused by sleep, timers, futexes, and I/O;
- `runq`: time from wakeup until the thread was scheduled to run again;
- `preempt/unknown`: off-CPU time for which no wakeup was observed, such as
  preemption, yielding, or an event missed under resource pressure.

This is scheduler-state attribution. It answers whether a slow call spent its
time executing, blocked, or waiting for CPU. It does not yet name the exact
kernel subsystem responsible for every blocked interval.

When the longest wait inside a traced function is a futex wait, attribution
also reports the futex address, operation, wait duration, and the latest thread
observed calling `FUTEX_WAKE` or `FUTEX_WAKE_BITSET` for the same address. If a
user stack is available, the wake caller's stack is symbolized:

```text
wait=futex operation=wait address=0x00005d9db3cf70e0 duration=248.643 ms
  waker PID 4312/TID 4315 (trace_lock_test)
  waker #0  libc.so.6  pthread_mutex_unlock
  waker #1  trace_lock_test  release_shared_resource at test/test_lock.c:21
  waker #2  trace_lock_test  lock_holder_main at test/test_lock.c:32
```

This detail is enabled automatically by `--attribution`, including asynchronous
hop attribution. For each function or hop, callweave retains only the
longest completed futex wait. The wake caller is strong causal evidence for
normal pthread mutex and condition-variable paths, but it is not guaranteed to
be a mutex owner: timeouts, signals, requeue operations, custom synchronization
algorithms, and an unsuccessful wake syscall can produce an unobserved or
candidate-only waker.

### io_uring request latency

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

### CQE to user callback

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

### libuv automatic adapter

The first libuv adapter covers native `uv_poll_t` watchers. It observes
`uv_poll_init`, `uv_poll_init_socket`, `uv_poll_start`, `uv_poll_stop`, and
`uv_close` to learn the relationship:

```text
uv_poll_t handle -> monitored FD -> registered callback
```

When `uv_poll_start` succeeds, Callweave resolves the callback pointer to its
file-backed ELF mapping and dynamically attaches entry and return uprobes.
The existing epoll tracer then connects kernel readiness to that handle and
reports ready-to-callback delay, callback execution time, scheduler
attribution, resource identity, and the callback stack.

No callback name, callback argument number, FD, or `epoll_event.data` value is
required:

```sh
sudo ./callweave -p PID --libuv
sudo ./callweave -p PID --libuv \
  --min-epoll-callback-us 500 --duration 20
```

For the smallest startup blind window, let Callweave launch the target:

```sh
sudo ./callweave --libuv --duration 20 \
  --exec ./server -- --port 8080
```

The ELF defining `uv_poll_start` is normally found automatically among the
target's mapped modules, or among the executable's dynamic dependencies in
`--exec` mode. Use the optional override only for a later `dlopen`, unusual
loader layout, or bundled libuv that cannot be inferred:

```sh
sudo ./callweave -p PID --libuv \
  --libuv-binary /opt/application/lib/libuv.so.1
```

The final output is headed `libuv summary`, identifies epoll as the Linux I/O
backend, retains the useful backend diagnostic sections, and adds a
`libuv adapter health` block with handle lifecycle, registration-event,
unique callback-attachment, and attachment-failure counts. Callback rows use
the actual `uv_poll_t *` as their automatically learned key.
JSON Lines mode emits the normal `epoll_callback`/`epoll_summary` records and
an additional final `libuv_summary` record.

There are two deliberate boundaries in this first version:

- With `-p PID`, libuv handles whose `uv_poll_init/start` calls finished before
  attachment cannot be reconstructed safely from a stable public API. Generic
  epoll registrations are still recovered from `/proc/PID/fdinfo`, but
  automatic callback attribution begins with later libuv registrations.
- The callback pointer must belong to a file-backed executable mapping so a
  uprobe can be attached. This covers native C/C++ callbacks, including
  stripped functions because their runtime address is sufficient. It does not
  yet identify a Node.js/V8 JIT JavaScript callback; that requires a separate
  runtime-specific adapter.

Build the optional example after installing `libuv1-dev`:

```sh
make test-libuv
```

Then use two terminals. The example prints its PID and waits five seconds
before registering its poll handle:

```sh
# Terminal 1
./test/trace_libuv_test 20

# Terminal 2
sudo ./callweave -p PID --libuv \
  --min-epoll-callback-us 1000 --epoll-top 5
```

The example writes to a nonblocking pipe every 50 ms and deliberately sleeps
for about 3 ms in every fifth poll callback, making the callback execution and
blocked-time attribution visible. It is also usable through `--exec`:

```sh
sudo ./callweave --libuv --duration 12 \
  --exec ./test/trace_libuv_test -- 20
```

### epoll event-loop diagnostics

Use standalone epoll mode to inspect event-loop wait behavior without knowing
a callback function in advance:

```sh
sudo ./callweave -p PID --epoll
sudo ./callweave -p PID --epoll --duration 10 --max-events 100
```

To guarantee observation from the target's first epoll operation, let
Callweave launch it after the BPF programs and ring buffers are ready:

```sh
sudo ./callweave --epoll --exec ./server -- --port 8080
```

`--exec PROGRAM` treats arguments after `--` as target arguments. When
Callweave itself was started through `sudo`, the target is returned to the
invoking user's UID, GID, and supplementary groups before `exec`. The target
is supervised as part of the capture and is stopped when tracing ends. An
exec gate starts epoll accounting at the target's successful `exec`, excluding
the suspended Callweave child-launcher's own file descriptors and epoll calls.

The tracer observes `epoll_wait`, `epoll_pwait`, and `epoll_pwait2`, successful
`epoll_ctl` changes, the common read/write/socket I/O syscalls performed after
a ready return, and the producers of eventfd, timerfd, and signalfd readiness.
Each detailed wait record contains the event-loop thread, epoll FD, wait
duration, return value, ready-event flags, application-defined `event.data`,
and the corresponding monitored FD when it can be recovered. A dispatch
record then connects that ready FD to the first matching I/O operation on the
same event-loop thread.

The final summary is computed from BPF aggregates and therefore includes
waits omitted by the detail threshold. It reports:

- wait calls, ready events, timeouts, interruptions, other errors, and dropped
  detail records;
- event loops grouped by TID and epoll FD, including average/maximum wait,
  full batches, ready-to-I/O latency, complete ready-to-next-wait cycle time,
  scheduler off-CPU/blocked/run-queue attribution, unhandled/handoff counts,
  I/O errors, and the user-space wait call site;
- successful registrations grouped by epoll FD and monitored FD;
- per-resource I/O calls, bytes, handler call sites, and potential incomplete
  EPOLLET drains;
- FD and epoll-instance generations, so a closed and numerically reused FD is
  not merged into the old resource;
- EPOLLONESHOT readiness/rearm counts and possible missing-rearm warnings;
- multiple waiters sharing one epoll instance, peak concurrent waiters,
  ready-event distribution, and EPOLLEXCLUSIVE observations;
- interest and observed event masks;
- socket endpoints, Unix sockets, eventfd, timerfd, pipes, and file paths when
  `/proc/PID` exposes them;
- eventfd writers, timerfd arms, and signalfd signal senders, including their
  source thread, user stack, source-to-ready latency, and attribution coverage;
- when configured, callback matches, ready-to-callback delay, execution time,
  on-CPU/blocked/run-queue attribution, and slowest callback stacks.

Long waits are not treated as slow work: an event loop normally blocks in
epoll while idle. The diagnosis instead highlights repeated full batches,
empty/busy polling, syscall errors, and opaque event data. A full batch only
means the supplied event array reached capacity; the summary calls it
`batch capacity pressure` after repeated observations rather than claiming
that backlog is proven.

Applications may put an FD, integer token, or pointer in `epoll_event.data`.
Callweave observes `epoll_ctl` to map that value back to the registered FD.
It also seeds registrations that existed before tracing from
`/proc/PID/fdinfo`. Two snapshots are taken after the BPF programs are
attached, while live `epoll_ctl` updates win any race with the snapshots.
The startup message and summary report how many registrations and epoll FDs
were recovered, together with snapshot conflicts or failures. If two
registrations in one epoll instance use the same data value, the returned
value is marked unresolved instead of guessing.
The seed and live BPF paths use the target PID namespace identity, so attaching
to an already-running process also works when WSL or a container exposes a PID
that differs from the kernel's raw TGID. Live `epoll_ctl` changes take
precedence over a concurrent fdinfo snapshot.

Late attachment recovers current registration state, not past timing. The
summary therefore labels `-p PID` captures as `post-attach only`; ready events,
dispatch latency, ET/ONESHOT mistakes, and FD lifetime changes that completed
before attachment cannot be reconstructed. `--exec` labels the observation
scope as `complete from target start`.

#### What epoll diagnostics help locate

The useful boundary is not merely how long `epoll_wait` sleeps. A long wait
normally means that the application was idle. Callweave instead separates:

```text
waiting for readiness -> FD became ready -> application started I/O
```

Use the report as follows:

| Symptom | Callweave evidence | Likely cause or next action |
| --- | --- | --- |
| A request arrived but handling started late | High average or maximum dispatch latency | Look for CPU-heavy callbacks, lock contention, synchronous work, or unfair event-loop scheduling. Move blocking work off the loop thread. |
| An edge-triggered connection stops making progress | `possible incomplete EPOLLET drain` | Read or accept in a loop until `EAGAIN`, or verify that the FD is closed/rearmed correctly. |
| An EPOLLONESHOT connection only fires once | `possible missing EPOLLONESHOT rearm` | Complete the handler and use `EPOLL_CTL_MOD` to re-enable the registration, unless it was deliberately closed. |
| Time between ready return and the next wait is large | High cycle time with on-CPU, blocked, and run-queue breakdown | High on-CPU points to expensive handler work; blocked time points to sleeping/locks; run-queue time points to CPU contention. |
| Several threads wait on the same epoll FD but one handles nearly everything | High maximum waiter share | Check workload affinity and starvation. For multiple epoll instances watching the same source, consider appropriate `EPOLLEXCLUSIVE` use. |
| An FD number appears to change identity | A new generation or `[closed/reused]` resource | Treat the generations as separate lifetimes and inspect close/dup/reopen races. |
| An event-loop thread consumes high CPU | Very frequent waits with very short wait durations | Check for busy polling, a level-triggered FD that remains ready, or a callback that did not consume the event. |
| Every returned batch is full | Repeated full batches and `batch capacity pressure` | Increase `maxevents`, drain batches faster, and inspect whether one resource is producing disproportionate readiness. |
| A ready FD is not followed by same-thread I/O | Increasing unhandled/handoff count | Check missing event branches. If work is intentionally transferred to another thread, treat this as a handoff rather than proof of a bug. |
| I/O fails after readiness | Per-loop or per-resource I/O errors | Inspect FD close/reuse races, connection lifecycle, and the reported handler stack. |
| One resource dominates the loop | High READY/HANDLED counts for one FD | Investigate a hot connection, starvation, unfair per-connection work, or a continuously ready FD. |
| The responsible source code is unknown | Ready-handler call site | Follow the first `read`, `recv`, `accept`, or related I/O stack to the handler implementation. |
| An eventfd wakes the loop unexpectedly | `eventfd` latest source and writer stack | Find the code path that wrote the counter, then inspect repeated or bursty writes. |
| A timer callback runs late | High `timerfd` schedule-to-ready latency | Check event-loop starvation, CPU contention, or an overloaded ready queue rather than blaming `epoll_wait`. |
| A signal-driven event appears unexpectedly | `signalfd` signal number, sender thread, and stack | Locate the `kill`, `tgkill`, or equivalent sender and verify signal routing and masking. |
| The event loop is slow but I/O is fast | High callback execution time in section `[10]` | Inspect the slowest callback stack and its on-CPU/blocked/run-queue split. |
| A callback starts long after epoll returned its FD | High `AVG/MAX R->CB` | Check earlier callbacks in the same ready batch, event-loop starvation, or unfair per-event work. |

For example, high dispatch latency on one socket together with an EPOLLET
warning means the socket was returned by epoll, the loop did not reach its
first I/O promptly, and the observed read sequence did not prove that the FD
was drained. The handler stack identifies where to begin reviewing the code.

The generic tracer associates readiness with I/O on the same event-loop
thread. A worker-thread handoff is therefore reported as unhandled/handoff,
not automatically as an error. If the application callback is known and
receives either the ready FD or the exact value registered in
`epoll_event.data`, the optional callback probe below provides an exact
user-space boundary. Runtime adapters are still needed when libuv, libevent,
Boost.Asio, or an application loop transforms that value into a different
wrapper before invoking the selected callback.

#### Callback execution attribution

Use `--epoll-callback` when a known function handles one ready event and one
of its first eight arguments contains either the raw FD or the exact
`epoll_event.data` value:

```sh
sudo ./callweave -p PID --epoll \
  --epoll-callback handle_ready_fd \
  --epoll-callback-key-arg 1 \
  --epoll-callback-match fd
```

The callback is assumed to be in `/proc/PID/exe`. Select a shared library or
another ELF explicitly when needed:

```sh
sudo ./callweave -p PID --epoll \
  --epoll-callback dispatch_connection \
  --epoll-callback-binary /opt/app/lib/libloop.so \
  --epoll-callback-key-arg 2 \
  --epoll-callback-match data
```

The `data` mode supports both scalar tokens stored in `data.u64` and object
pointers stored in `data.ptr`. Callweave uses the registration captured from
`epoll_ctl` to translate the callback value back to its original FD and FD
generation. `--epoll-callback-match` is required: select `fd` when the callback
argument is the descriptor itself, or `data` when it is the unchanged
`epoll_event.data` value. Callweave deliberately does not infer the mode,
because a small integer data token can also be a valid active FD.

At callback entry, Callweave matches `thread + callback key` against the
unresolved resources in the current epoll batch. The return probe then
measures:

```text
FD ready -> callback entry -> callback return
             |                 |
             + ready delay     + execution and scheduler breakdown
```

Text output includes individual `EPOLL CALLBACK` records and a final
`[10] Callback execution` table. The table ranks resources by maximum callback
duration and reports average/maximum ready-to-callback delay, average/maximum
work time, and average on-CPU, blocked, and run-queue time. The callback record
and summary table show the original callback key and its resolved FD, for
example `6 -> fd=6` in `fd` mode or
`0x00007fff12345678 -> fd=6` in `data` mode. The callback record also carries
the eventfd/timerfd/signalfd wake source when one is available.

Limit high-volume detail while retaining all BPF aggregates:

```sh
sudo ./callweave -p PID --epoll \
  --epoll-callback handle_ready_fd \
  --epoll-callback-key-arg 1 \
  --epoll-callback-match fd \
  --min-epoll-callback-us 500
```

The implementation pairs nested and recursive invocations independently per
thread, up to eight active callback levels. `Callback match/done` in the
summary exposes callbacks that entered but did not return normally during the
capture. The overview also separates matches found by FD and by data. A wrong
key argument or match mode increases `unmatched`; a late attachment can also
leave the first callback unmatched when its corresponding ready return
occurred before tracing. Callweave does not scan or guess callback arguments
because unrelated integers and pointers can equal active keys.

This generic mode requires the callback to execute on the epoll waiter thread
and receive either the raw FD or an unchanged `epoll_event.data` value. If one
data value is simultaneously registered for multiple FDs, the mapping is
reported as ambiguous rather than guessed. A callback that receives a
different framework handle, an enclosing object, or a transformed/tagged
pointer still requires a runtime-specific adapter.
The existing `Unhandled/handoff` counter remains specifically a
ready-to-I/O measurement, so a callback that intentionally performs no I/O can
be callback-matched while still appearing unconsumed in that separate metric.

#### Wake-source attribution

Wake-source attribution is enabled automatically with `--epoll`; no additional
option is required. It extends the normal ready-to-handler path in the opposite
direction:

```text
eventfd write / timerfd arm / signal send
    -> monitored FD becomes ready
    -> epoll returns it
    -> event-loop thread performs I/O
```

For eventfd, Callweave records successful `write` calls made by the traced
process, combines writes that occur before the next readiness return, and
reports their count, accumulated value, latest writer, and writer stack. A
write from another process can make the FD ready, but generic `-p PID` tracing
does not currently capture that external writer; such a readiness is retained
and labeled unattributed instead of being assigned to the wrong source.

For timerfd, Callweave records the latest successful `timerfd_settime`, its
initial and interval values, and the arm stack. Relative timers also report
schedule-to-ready lateness. One periodic arm may produce many ready events, so
`SRC OPS` counts distinct arm operations rather than expirations. Absolute
timers keep the arm information but do not claim a comparable lateness because
their clock domain may not match BPF monotonic time.

For signalfd, Callweave reads the monitored signal mask and associates a ready
event with the latest matching kernel `signal_generate` event for the target
process. The report includes the signal number and sender stack when the signal
originated in user space. Under a burst of different pending signals, this is a
conservative latest-source association, not a reconstruction of the kernel's
entire pending-signal queue.

The `[9] Wake-source attribution` summary reports READY, MATCHED, source
operation count, average/maximum source-to-ready latency, and the latest source
stack for each special FD. `MATCHED / READY` is the attribution coverage; a
low ratio usually means attachment began after a source operation, the source
came from outside the traced process, or a kernel-originated event has no
user-space producer stack.

Current special-FD metadata is restored from `/proc/PID/fdinfo` during late
attachment, so Callweave can still identify eventfd, timerfd, and signalfd
resources that already exist. It cannot reconstruct producer operations or
stacks that completed before BPF attachment.

The bundled test exercises all three sources:

```sh
sudo ./callweave --epoll --duration 10 \
  --exec ./test/trace_epoll_test -- 60
```

#### Anonymous kernel resources

Resources such as:

```text
anon_inode:[timerfd]
anon_inode:[eventfd]
anon_inode:[signalfd]
anon_inode:[eventpoll]
anon_inode:[io_uring]
```

are anonymous inode objects created by the kernel. They have a `struct file`
and support normal FD operations such as `read`, `close`, `dup`, and
`epoll_ctl`, but they do not correspond to a pathname on disk and cannot be
reopened with `open`.

For `anon_inode:[timerfd]`, timer expiration makes the FD readable, epoll
returns `EPOLLIN`, and reading the FD returns the number of expirations. The
object remains alive while a process holds a reference to its FD. Inspect the
kernel resource behind an FD with:

```sh
readlink /proc/PID/fd/FD
cat /proc/PID/fdinfo/FD
```

An `anon_inode` label therefore does not mean that resource resolution failed.
It identifies a kernel-backed FD whose type is shown inside the brackets.

For high-rate loops, keep aggregate statistics while limiting detailed output:

```sh
sudo ./callweave -p PID --epoll \
  --min-epoll-wait-us 1000 \
  --min-epoll-dispatch-us 100 \
  --epoll-top 10
```

JSON Lines output contains `epoll_wait`, `epoll_dispatch`, and, when enabled,
`epoll_callback` records followed by one `epoll_summary` record:

```sh
sudo ./callweave -p PID --epoll --format json \
  --output /tmp/callweave-epoll.jsonl
```

Without `--epoll-callback`, generic mode associates readiness only with
subsequent syscalls on the same event-loop thread. Use the callback option for
a known raw-FD callback, or a runtime adapter when the event loop exposes only
opaque framework objects.

For edge-triggered registrations, Callweave reports a
`possible incomplete EPOLLET drain` when it observes a read after readiness but
does not observe EAGAIN, a short read, EOF, close, or `EPOLL_CTL_MOD` rearm
before the thread waits again. This is deliberately a heuristic, not proof:
work handed to another thread is reported as unhandled/handoff rather than an
ET bug, and eventfd/timerfd/signalfd single-read counter semantics are
suppressed as warnings. `Pending at stop` is the final ready batch that had not
yet reached the next `epoll_wait*` entry, where dispatch accounting is closed.
The drain evidence understands bounded `readv` iovecs, `recvmsg`,
`recvmmsg`, `accept`/`accept4`, and `splice`; `MSG_PEEK` is explicitly shown
because it does not consume queued data. The checks remain conservative:
buffers with more than eight iovecs and application-specific wrappers can
reduce the available evidence.

For `EPOLLONESHOT`, a ready result disables that registration until
`EPOLL_CTL_MOD` rearms it. Callweave marks a potential missing rearm when the
event-loop thread reaches its next wait without a rearm or close. This is a
diagnostic candidate rather than proof if another thread owns the rearm.

FD identity is reported as `fd + generation`. Successful close and dup-family
operations advance the tracked lifetime, while a later `epoll_ctl` registration
uses the new generation. This prevents statistics for a newly reused numeric
FD from being silently combined with the old registration. Descriptor aliases
created before tracing may still require application context because epoll
tracks the underlying open file description, not only the integer FD.

If the asynchronous source is not known yet, inspect the most recent thread
that woke the final target:

```sh
sudo ./callweave -p 1234 --discover-async write_result
```

Discovery prints the waker's user stack, the elapsed time from wakeup to target
entry, and a suggested `--async-hop` template. The suggestion deliberately
leaves the source argument as `?`, because eBPF can observe raw arguments but
cannot infer which one is the shared task pointer or request ID:

```text
candidate source function: submit_storage_task
suggested template:
  --async-hop submit_storage_task,?,write_result,1 write_result
```

If the target key is not argument 1, add `--async-target-arg N` while
discovering. Discovery is a heuristic: it reports the latest scheduler waker,
which is often a queue submitter using a condition variable or futex, but it is
not proof of application-level causality. To bound overhead, this mode records
wakers in the selected process; timer expiry, I/O completion, signals, and
kernel-originated wakeups may therefore have no candidate user stack. Use the
candidate stack to identify the enqueue/submit function, then confirm the
shared argument before switching to `--async-hop`.

The first target hit after attachment initializes the kernel-global process
identity used by discovery, so candidate output normally begins with a
subsequent wakeup rather than that first event.

Stitch a cross-thread asynchronous call chain:

```sh
sudo ./callweave -p 1234 \
  --async-source submit_async_task \
  --async-source-arg 1 \
  --async-target-arg 1 \
  process_task
```

The source and target arguments must contain the same nonzero key. A task
object pointer is a natural key, but an integer request ID also works. Argument
positions are 1-based and currently support the first eight integer or pointer
arguments. The source position defaults to argument 1, while an omitted target
position defaults to scanning arguments 1-8. Pass `--async-target-arg N` when
the target position is known and should be fixed explicitly.

For example, given:

```c
void enqueue_request(const char *queue, struct request *request);
void process_request(struct request *request);
```

the shared `request` pointer is source argument 2 and target argument 1, so use
`--async-source-arg 2 --async-target-arg 1`. The tool reads the raw argument
value as a key; it does not need to know the C type or dereference the pointer.

The source function is assumed to be in the target ELF. If it is in another
executable or shared library, specify it explicitly:

```sh
sudo ./callweave -p 1234 \
  --async-source enqueue_work \
  --async-source-binary /absolute/path/to/libqueue.so \
  --async-source-arg 2 \
  --async-target-arg 1 \
  process_work
```

Each saved context is consumed by the first matching target call. Unmatched
contexts expire after 30 seconds by default; change the limit with
`--async-max-age-ms MS`. This one-shot behavior is intended for task queues.
Fan-out, where one submitted task deliberately runs in multiple workers,
requires a separate source probe or future multi-consumer support.

For multiple asynchronous handoffs, repeat `--async-hop`. Its format is
`SOURCE,SOURCE_ARG,TARGET[,TARGET_ARG]`, and the target of the last hop must be
the final positional function. `TARGET_ARG` can be omitted or written as
`auto`. In that case, callweave scans target arguments 1-8 and accepts the
event only when exactly one argument matches a saved source key. Async tracing
automatically enables function timing and scheduler attribution:

```sh
sudo ./callweave -p 1234 \
  --async-hop enqueue_request,2,process_request \
  --async-hop enqueue_storage_task,2,write_result \
  write_result
```

An explicit target position remains available, for example
`enqueue_request,2,process_request,1`. It avoids up to five map lookups at each
target entry and is preferable for very hot target functions. It is also safer
when several target arguments can coincidentally equal outstanding scalar
keys. Auto mode rejects such ambiguous events instead of guessing.

Here `process_request` is both the target of the first hop and the execution
scope in which the second source, `enqueue_storage_task`, runs. The tool
inherits the first lineage, appends the second producer stack, and prints one
completed causal chain when `write_result` returns. Up to eight hops are
retained. If a longer chain is observed, the oldest hop is dropped and the
output reports how many hops were truncated.

Each hop contains:

- `queue`: source-function entry to target-function entry, including enqueue,
  queue waiting, wakeup, and scheduling delay;
- `work`: target-function entry to the next handoff for intermediate hops, or
  target-function entry to return for the final hop;
- `oncpu`, `blocked`, `runq`, and `preempt/unknown`: scheduler attribution
  within `work`;
- `dominant`: the largest target-work component, useful as an immediate
  classification rather than an exact syscall or lock name.

Example:

```text
async hop 0 submit_compute_task -> process_request ...
  queue=18.421 ms work=40.173 ms oncpu=91.822 us blocked=40.061 ms runq=20.131 us dominant=blocked
async hop 1 submit_storage_task -> write_result ...
  queue=73.614 ms work=80.142 ms oncpu=77.315 us blocked=80.038 ms runq=26.685 us dominant=blocked
```

The multi-hop form currently assumes that all named source and target
functions are in the target ELF. Hop numbers are zero-based: three thread
segments have two handoffs, printed as `async hop 0` and `async hop 1`.

For a repeatable trace, put the target, hops, and output limits in a
configuration file. `examples/thread-pool.yaml` contains:

```yaml
target:
  function: write_result

hops:
  - source: submit_compute_task
    source_arg: 2
    target: process_request
    target_arg: 1
  - source: submit_storage_task
    source_arg: 2
    target: write_result
    target_arg: 1

filters:
  min_total_ms: 100
  min_queue_ms: 10
  min_work_ms: 20
  max_events: 10
  duration: 30
  diagnostic_interval_ms: 1000
```

Validate it without loading BPF, then run it against a process:

```sh
./callweave --check-config examples/thread-pool.yaml
sudo ./callweave -p 1234 --config examples/thread-pool.yaml
```

The parser intentionally accepts this documented YAML subset rather than every
YAML feature. Each hop requires `source`, `source_arg`, and `target`.
`target_arg` is optional and defaults to auto detection; it may also be written
as `target_arg: auto`. Explicit argument positions are 1-8, and at most eight
hops are accepted. Command-line filter options override values loaded from the
file regardless of option order.

The same slow-chain controls can be used with explicit `--async-hop` options:

```sh
sudo ./callweave -p 1234 \
  --async-hop enqueue_request,2,process_request,1 \
  --async-hop enqueue_storage_task,2,write_result,1 \
  --min-total-ms 100 \
  --min-queue-ms 10 \
  --min-work-ms 20 \
  --max-events 10 \
  --duration 30 \
  write_result
```

Filter conditions are combined: `min-total-ms` compares the sum of queue and
work time across the retained chain, while `min-queue-ms` and `min-work-ms`
require at least one hop to reach their thresholds. When a chain filter or
`--max-events` is active, entry events are suppressed and only completed
matching chains are printed. `--duration` is also available for non-async
traces.

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

## Live queue and thread-pool diagnostics

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
  --report /tmp/callweave-report.html
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

The original explicit-path form remains available and traces every process
executing the selected ELF:

```sh
sudo ./callweave /absolute/path/to/program function_name
```

When a PID is supplied, the main executable is discovered automatically through
`/proc/PID/exe`:

```sh
sudo ./callweave -p 1234 function_name
```

Select an already loaded shared library by exact basename or absolute mapped
path:

```sh
sudo ./callweave -p 1234 --module libc.so.6 malloc
```

If the same basename refers to more than one mapped file, `callweave` lists
the candidates and requires an absolute module path instead of guessing.

Search all mapped ELF files for a defined function symbol without attaching a
probe:

```sh
sudo ./callweave -p 1234 --find-symbol malloc
sudo ./callweave -p 1234 --module libc.so.6 --find-symbol malloc
./callweave --binary ./test/trace_test --find-symbol function_to_trace
```

The search output includes both the ELF symbol value and, when derivable from a
`PT_LOAD` segment, the file offset accepted by `--offset`:

```text
/usr/lib/x86_64-linux-gnu/libc.so.6
  symbol=malloc value=0x98860 offset=0x98860
```

Attach directly to a known ELF file offset without requiring a symbol:

```sh
sudo ./callweave --binary ./program --offset 0x11c9
sudo ./callweave -p 1234 --binary ./program --offset 0x11c9
```

The uprobe is attached to the ELF independently of process lifetime. When
`-p` is present, the BPF program filters events by the PID as seen in the
tracer's PID namespace before collecting a stack.

`BINARY` may be an executable or a shared library. `FUNCTION` must be present in
its ELF symbol table. C++ symbol support depends on the symbol accepted by
libbpf for uprobe attachment; output names are demangled by `addr2line -C`.
`--find-symbol` reports exact, defined `STT_FUNC` and GNU IFUNC names from
`.symtab` or `.dynsym`; it deliberately ignores undefined import entries.

Programs compiled with debug information provide the best source locations.
Stripped binaries can still produce raw addresses and module names but may not
produce function or line information.

## Quick test

Build everything, start the example in one terminal, and note its PID:

```sh
make
./test/trace_test
```

In another terminal:

```sh
sudo ./callweave -p PID function_to_trace
```

Each loop iteration should produce a stack similar to:

```text
[2026-07-25 12:00:00] PID 1234/TID 1235 (trace_test)
  #0   0x000055... trace_test               function_to_trace at test/test.c:18
  #1   0x000055... trace_test               worker_main at test/test.c:65
  #2   0x00007f... libc.so.6                start_thread at ...
```

Enable return values and execution time during the quick test:

```sh
sudo ./callweave -p PID --ret --time function_to_trace
```

The entry stack is followed by a completion event:

```text
[2026-07-23 12:00:00] PID 1234/TID 1234 (trace_test) RETURN ret=0x0000000000123456 (1193046) duration=8.742 us
```

The return value is the architecture's raw integer return register. It is
useful for integer, status-code, and pointer returns, but the tracer does not
know the C type and cannot decode floating-point, aggregate, or indirect
returns. Duration uses the kernel monotonic clock and includes all time between
entry and return, including time when the thread is preempted or blocked.
Functions that do not return normally (for example because of `longjmp`,
thread exit, or process exit) do not produce a return event.

The test function includes a short sleep so that attribution produces a visible
blocked interval:

```sh
sudo ./callweave -p PID --attribution function_to_trace
```

To test io_uring without installing liburing, start the raw-syscall example:

```sh
./test/trace_io_uring_test
```

It prints its PID, waits two seconds, and then continuously submits batches
containing `NOP`, `WRITE`, `READ`, `TIMEOUT`, and an intentionally invalid
`READ` SQE until you press Ctrl+C. Alternate batches end with an unsupported
opcode to exercise `io_uring_req_failed`. Each batch also links a safe
`NOP -> NOP` pair and calls `process_io_completion(user_data)` for every
consumed CQE. In another terminal, run:

```sh
sudo ./callweave -p PID --io-uring
```

To exercise the complete CQE-to-callback path:

```sh
sudo ./callweave -p PID --io-uring \
  --io-callback process_io_completion \
  --io-callback-arg 1
```

Each traced request is split into an `SQE submit` section, a matching
`CQE complete` section, the `SQE->CQE` latency, and the submitter stack.
`WRITE` and `READ` demonstrate file descriptors and byte-count CQE results;
`TIMEOUT` demonstrates an expected `-ETIME` result and visibly longer
completion latency; the invalid read demonstrates `--io-errors-only`.
The final summary groups latency by opcode, file descriptor, and submit stack.
It also shows the ring configuration, CQ waits, linked NOP requests, and the
temporary-file resource path.

For a finite run, pass the number of requests:

```sh
./test/trace_io_uring_test 20
```

Or build and run both sides together:

```sh
make demo-io-uring
```

To test epoll resource and batch diagnostics, start the example separately:

```sh
./test/trace_epoll_test
```

It waits two seconds, creates an epoll instance, and registers an eventfd,
timerfd, edge-triggered Unix socket, and EPOLLONESHOT Unix socket with
application-defined data tokens. Trace it from another terminal:

```sh
sudo ./callweave -p PID --epoll \
  --min-epoll-wait-us 1 \
  --epoll-top 3
```

Omit the iteration count to keep the target alive until Ctrl+C. Pass a larger
count when a finite standalone run is preferable, or run both sides together:

```sh
./test/trace_epoll_test
./test/trace_epoll_test 200
make demo-epoll
```

The regular socket uses EPOLLET and drains until EAGAIN. To intentionally leave
an edge-triggered socket readable and verify the warning:

```sh
./test/trace_epoll_test --bad-et
sudo ./callweave -p PID --epoll --epoll-top 5
```

The other focused scenarios can be combined:

```sh
# Skip EPOLL_CTL_MOD after the first ONESHOT event.
./test/trace_epoll_test --bad-oneshot

# Run two threads waiting on the same epoll instance.
./test/trace_epoll_test --multi-waiter

# Exercise close/dup descriptor-generation tracking.
./test/trace_epoll_test --fd-reuse

# Make the signalfd callback block for about 2 ms.
./test/trace_epoll_test --slow-callback

# Register resource objects through epoll_event.data.ptr.
./test/trace_epoll_test --data-ptr

# Run every intentionally difficult scenario through the demo helper.
sudo ./test/run_epoll_demo.sh \
  --bad-et --bad-oneshot --multi-waiter --fd-reuse
```

To verify attachment to a process whose epoll registrations already exist:

```sh
sudo ./test/run_epoll_demo.sh --late-attach
```

The script waits until the target has completed `epoll_ctl` setup before
starting Callweave. The ready events should still resolve to concrete FDs
through the fdinfo seed path, and `Bootstrap state` should report recovered
registrations. To verify capture from the first operation instead:

```sh
sudo ./callweave --epoll \
  --epoll-callback epoll_test_data_callback \
  --epoll-callback-key-arg 1 \
  --epoll-callback-match data \
  --min-epoll-callback-us 500 \
  --duration 8 \
  --exec ./test/trace_epoll_test -- 100 --slow-callback --data-ptr
```

The final summary should report `Observation scope: complete from target
start`, exactly the target's epoll calls, callback matches for every resolved
ready FD under `matched by fd/data: 0 / N`, and zero bootstrapped
registrations. The signalfd callback sleeps briefly on purpose so its blocked
time is visible in callback attribution.

The example also passes a task pointer from the main thread through a small
queue to a worker thread. Use it to test asynchronous stitching:

```sh
sudo ./callweave -p PID \
  --async-source submit_async_task \
  function_to_trace
```

When the target returns, the output shows the producer stack with an `async`
prefix and reports that hop's queue time, target work time, and scheduler
breakdown. `--time` and `--attribution` are enabled automatically.

For a dedicated asynchronous test, run the second example program:

```sh
./test/trace_async_test
```

It prints its PID and the exact tracing command. The request passes through
three threads and two queues:

```sh
sudo ./callweave -p PID \
  --async-hop enqueue_request,2,process_request,1 \
  --async-hop enqueue_storage_task,2,write_result,1 \
  write_result
```

The resulting lineage is
`http_handler -> enqueue_request`, then
`process_request -> enqueue_storage_task`, followed by the current
`storage_worker_main -> write_result` stack.

To test target-argument auto detection with a deeper and less artificial
pipeline, run:

```sh
./test/trace_complex_async_test
```

The program uses four pipeline threads, three queues, and a transient storage
lock-holder thread. Each stage performs nested synchronous calls, and each
handoff deliberately uses a different key. The three target functions receive
those keys in arguments 2, 3, and 8 respectively. On x86-64, the last key is
stack-passed rather than held in an argument register. The storage stage also
waits on a contended mutex so the final hop demonstrates futex attribution.
Trace it with the supplied configuration:

```sh
sudo ./callweave -p PID \
  --config examples/complex-multi-hop.yaml \
  --report /tmp/callweave-complex.html
```

Or use the equivalent command without any target argument positions:

```sh
sudo ./callweave -p PID \
  --async-hop submit_decode_task,2,decode_request \
  --async-hop submit_enrich_task,1,enrich_request \
  --async-hop submit_persist_task,2,persist_result \
  --max-events 5 \
  persist_result
```

A completed chain contains `async hop 0`, `async hop 1`, and `async hop 2`,
with `target-arg=2`, `target-arg=3`, and `target-arg=8`. The target argument is
reported so an automatically discovered configuration can later be made
explicit if lower probe overhead is important.

To test futex wait-resource attribution, run:

```sh
./test/trace_lock_test
```

Then use the PID printed by the program:

```sh
sudo ./callweave -p PID --time --attribution function_to_trace
```

`function_to_trace` waits on a mutex held for roughly 250 ms by
`lock_holder_main`. The return event should report the futex address and show
the holder's unlock path as the waker stack.

For a more realistic example with two reusable worker pools, bounded queues,
bursty submissions, and blocking target work, run the complete demo:

```sh
make demo-async
```

This builds the project, starts `test/trace_thread_pool_test`, discovers its
PID, and runs the following trace automatically:

```sh
sudo ./callweave -p PID \
  --async-hop submit_compute_task,2,process_request,1 \
  --async-hop submit_storage_task,2,write_result,1 \
  write_result
```

The two pools deliberately run more slowly than the producer. This makes queue
growth visible, while sleeps inside `process_request` and `write_result`
produce a clear `dominant=blocked` classification. Press Ctrl+C to stop both
the tracer and the example process.

The same example is suitable for discovery and configuration tests:

```sh
./test/trace_thread_pool_test
# Use the PID printed by the program:
sudo ./callweave -p PID --duration 5 --discover-async write_result
./callweave --check-config examples/thread-pool.yaml
sudo ./callweave -p PID --config examples/thread-pool.yaml \
  --max-events 2 --duration 10
```

Generate a short visual report from the same test:

```sh
sudo ./callweave -p PID --config examples/thread-pool.yaml \
  --max-events 20 --report /tmp/callweave-report.html
```

Exact frames vary with the compiler, libc, optimization settings, and kernel
stack-walking support.

## Troubleshooting

- **`failed to attach uprobe`**: verify the binary path and inspect symbols with
  `nm -an BINARY` or `readelf -Ws BINARY`.
- **`unable to collect user stack`**: ensure the architecture and kernel support
  user stack walking. Frame pointers and debug information improve results.
- **`?? at ??:0`**: the module is stripped, debug symbols are unavailable, or
  the mapped file was deleted after the process started.
- **`cannot read /proc/PID/maps`**: the process may have exited before the event
  was consumed. PID namespace translation is automatic; if it fails, the
  output also reports the kernel-global PID and the translation error.
- **Permission errors**: run as root or configure the required BPF and perf
  capabilities for your kernel and distribution.
- **Attribution tracepoint attachment fails**: verify that the kernel exposes
  the `sched_switch`, `sched_wakeup`, `sys_enter`, and `sys_exit` raw
  tracepoints and that the process has the required BPF/perf privileges.
  Discovery additionally uses `sched_waking`. Running as root is the simplest
  test.
- **No async origin is printed**: verify that both selected argument positions
  contain exactly the same nonzero pointer or integer value. Also check that
  the target runs before `--async-max-age-ms` expires. The context is
  intentionally consumed only once.
- **Discovery reports no waker stack**: make sure the target thread blocks and
  is subsequently woken while discovery is running. Kernel-originated wakeups
  may not have a useful user stack; stack walking also depends on kernel and
  architecture support.
- **Dropped events under heavy load**: the ring buffer is deliberately bounded.
  This tool is intended for targeted tracing rather than very hot functions.

## Design overview

The userspace loader attaches `trace_function` to the requested symbol.
When the uprobe fires, the BPF program records process metadata and calls
`bpf_get_stack(..., BPF_F_USER_STACK)`. With `--ret` or `--time`, it also stores
the entry timestamp in a per-thread nested-call state and attaches
`trace_function_return` as a uretprobe. The return probe pairs the
innermost outstanding call, reads the raw return register, and calculates the
elapsed monotonic time. With `--attribution`, raw scheduler switch and wakeup
tracepoints accumulate off-CPU, blocked, and run-queue intervals for every
active nested call. Raw syscall entry and exit tracepoints retain the longest
futex wait for the currently executing invocation. Wake operations are keyed
by process and futex address so the result can include the candidate wake
caller and its user stack. The loader consumes events, derives on-CPU time,
reads the
process's memory mappings, computes each ELF load bias from its `PT_LOAD`
segments, groups frames by module, and invokes `addr2line` without using a
shell. Async source probes store stack IDs and metadata in an LRU map keyed by
process and the selected argument. Intermediate target probes bind a consumed
lineage to the current thread until the target function returns, allowing a
later source call to inherit and extend it. Scheduler tracepoints attribute
each intermediate target's work before the next handoff. The final target
keeps the lineage until its return probe completes the last hop, then emits up
to eight hop descriptors. Userspace retrieves their producer stacks from a BPF
stack-trace map, symbolizes each segment, and prints a single completed causal
chain. In discovery mode, `sched_waking` records wakeups originating in the
selected process and keys the latest waker stack by target thread. Target
entry consumes that record so userspace can present a likely handoff site
without requiring the async source function in advance.
