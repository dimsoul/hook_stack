<!-- SPDX-License-Identifier: MIT -->

# libuv: `work_cb` completed, but `after_work_cb` was delayed

[Documentation index](../README.md) · [Project README](../../README.md)

## Reported symptom

A real Stack Overflow question reports that Linux/libuv calls
`after_work_cb` about 50 ms after `work_cb` has finished. That observation alone
cannot distinguish a libuv worker-pool delay from an event loop that is unable
to dispatch the already-completed work.

Callweave models the lifecycle using the request's `uv_work_t *` as the causal
key:

```text
submit_work entry
    -> worker-pool queue
work_cb entry
    -> worker execution
work_cb completed
    -> event-loop dispatch wait
after_work_cb entry and execution
```

The important boundary is `work_cb completed`. The second hop therefore uses
`source_phase: exit` and `handoff: libuv`; measuring from `work_cb` entry would
incorrectly mix worker execution into the callback delay. The libuv handoff
annotation also observes the public `uv_async_send()` API, without depending
on private or stripped libuv symbols.

## Reproduce it

Install libuv development headers and build:

```sh
sudo apt install libuv1-dev
make test-libuv
```

Start the target:

```sh
./test/trace_libuv_work_test \
  --iterations 80 \
  --block-loop-ms 50
```

In another terminal, use the printed PID:

```sh
sudo ./callweave -p PID \
  --config examples/libuv-work-delay.yaml \
  --report ./callweave-libuv-work-delay.html
```

The test intentionally runs a 50 ms timer callback on the event-loop thread
while `work_cb` sleeps for about 2 ms in libuv's worker pool. A representative
chain should therefore show:

```text
submit_work started -> work_cb
                              queue: small       work: about 2 ms
work_cb completed -> after_work_cb
  completion publish           small
  uv_async_send                small
  loop-active/backlog          about 48 ms
  epoll wait/wakeup            small
  ready-to-callback            small
  after_work_cb execution      small
```

## Diagnosis and fix

In this reproduction, the worker is not stuck and libuv has not inserted a
fixed 50 ms timer. The work completes while another callback still owns the
event-loop thread. `after_work_cb` becomes runnable, but cannot execute until
that callback returns. The loop only re-enters `epoll_wait*` near the end of
the delay, so Callweave assigns the preceding interval to
`loop-active/backlog` rather than incorrectly calling all of it epoll wakeup
latency.

The fix is to keep event-loop callbacks short: move blocking or CPU-heavy work
to a worker, split it into bounded chunks, or otherwise return control to the
loop promptly. Confirm the diagnosis with the control run:

```sh
./test/trace_libuv_work_test \
  --iterations 80 \
  --block-loop-ms 0
```

The `work_cb completed -> after_work_cb` queue interval should collapse while the
worker execution interval remains about 2 ms. For a captured control report,
run the same tracer command with `--min-total-ms 0`; this overrides the case
configuration's 10 ms slow-chain filter.

This case demonstrates a diagnostic pattern, not a claim that every
application reporting 50 ms has the same cause. Run the same two-hop trace in
the affected binary to determine whether its time is in worker-pool queueing,
worker execution, or post-completion event-loop dispatch.

Original report:
[Stack Overflow: libuv `uv_queue_work()` delay](https://stackoverflow.com/questions/76929291/libuv-uv-queue-work-delay).
