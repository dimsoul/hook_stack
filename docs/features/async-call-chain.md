<!-- SPDX-License-Identifier: MIT -->

# Asynchronous call-chain tracing

[Documentation index](../README.md) · [Project README](../../README.md)

## Discover a handoff

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


## Trace one handoff

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


## Trace multiple handoffs

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


## Configuration files and filters

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
