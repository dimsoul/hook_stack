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
