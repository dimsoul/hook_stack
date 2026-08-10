<!-- SPDX-License-Identifier: MIT -->

# libuv: slow DNS stalls unrelated serial work

[Documentation index](../README.md) | [Project README](../../README.md)

## Reported symptom

A node-serialport issue reported that asynchronous serial reads and writes,
normally completing dozens of times per second, became delayed by several
seconds whenever the application made requests over a slow network. Fast
network access worked, and serial traffic without network access worked. The
original symptom did not reveal which subsystem owned the missing time.

The investigation eventually found two decisive controls:

- setting `UV_THREADPOOL_SIZE=N` allowed exactly N data events before the
  application stalled;
- a filesystem-only substitute reproduced the delay when DNS was slow, while
  using an IP address avoided it.

The original reports are
[node-serialport #797](https://github.com/serialport/node-serialport/issues/797)
and the related [nodejs/node #8436](https://github.com/nodejs/node/issues/8436).
They establish the real-world symptom and its shared-libuv-thread-pool cause.

## Diagnostic reconstruction

The historical JavaScript and hardware setup is no longer a stable reproducer,
so `test/test_libuv_threadpool_contention.c` preserves the relevant native
concurrency:

- four `dns_lookup_work` callbacks enter libuv's default four-worker pool;
- each callback deliberately blocks for five seconds, modeling a blocking
  `getaddrinfo()` during slow DNS;
- six unrelated `serial_write_work` callbacks are then queued;
- each serial callback performs only a one-byte write to `/dev/null`.

The five-second DNS delay is injected. It is not presented as a measurement of
a live resolver. A separate validation used real `getaddrinfo()` calls against
an unreachable resolver and produced the same ordering and timing shape; the
bundled version avoids changing resolver settings and remains deterministic.

Build and run the complete demonstration with one command:

```sh
make demo-libuv-threadpool
```

This builds the optional libuv workload, installs the configured asynchronous
probes, launches the workload with libuv's default four-worker pool, and writes
`callweave-libuv-threadpool-contention.html`. Its equivalent explicit command
is:

```sh
sudo env UV_THREADPOOL_SIZE=4 ./callweave \
  --config examples/libuv-threadpool-contention.yaml \
  --report ./callweave-libuv-threadpool-contention.html \
  --exec ./test/trace_libuv_threadpool_contention -- \
  --startup-delay-ms 0
```

## Evidence

For the six serial-like operations, Callweave measured:

```text
matched serial work: 6
pending peak:        6
average queue:       4.900 s
average work:       15.320 us
```

The serial callbacks themselves were fast. Almost the entire delay occurred
between `submit_serial` and entry to `serial_write_work`, before any serial
code ran.

A second trace identified what occupied the workers:

```sh
sudo ./callweave -p PID \
  --binary ./test/trace_libuv_threadpool_contention \
  --attribution --duration 10 \
  dns_lookup_work
```

All four libuv workers entered `dns_lookup_work` together. Each call lasted
5.000084--5.000124 seconds, with 14--35 us on CPU and about five seconds
blocked or off CPU.

As a causal control, run the same workload with eight workers:

```sh
UV_THREADPOOL_SIZE=8 ./test/trace_libuv_threadpool_contention
```

The serial queue delay collapses because workers remain available. This is a
validation of the diagnosis, not a general recommendation to enlarge the
thread pool.

## Diagnosis

Slow DNS work and serial/native work share libuv's fixed-size worker pool. Four
blocking DNS lookups occupy all four default workers. The serial operations are
already submitted but cannot start, so they wait about five seconds in the
worker queue and then finish almost immediately.

```text
four blocking DNS jobs
  -> all four shared libuv workers occupied
  -> unrelated serial jobs wait in the queue
  -> serial work starts only after DNS releases a worker
```

Callweave therefore localizes the reported delay to cross-subsystem worker-pool
contention, rather than the serial device, the event loop, or slow execution of
the serial callback itself.
