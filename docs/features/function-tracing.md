<!-- SPDX-License-Identifier: MIT -->

# Function tracing and scheduler attribution

[Documentation index](../README.md) · [Project README](../../README.md)

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


## Target and binary selection

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
