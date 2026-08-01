<!-- SPDX-License-Identifier: MIT -->

# Testing guide

[Documentation index](README.md) · [Project README](../README.md)


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
