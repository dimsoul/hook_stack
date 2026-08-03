<!-- SPDX-License-Identifier: MIT -->

# libuv runtime adapter

[Documentation index](../README.md) · [Project README](../../README.md)


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
sudo ./callweave -p PID --libuv --live --duration 20
```

The default is summary-only output: Callweave keeps all BPF aggregates and
prints the final diagnosis without streaming each ready event. Use `--live`
to stream slow or anomalous paths, or `--verbose` to stream every wait,
dispatch, and callback detail:

```sh
sudo ./callweave -p PID --libuv
sudo ./callweave -p PID --libuv --live
sudo ./callweave -p PID --libuv --verbose
```

In `--live` mode, normal long idle waits remain quiet; wait errors,
unhandled/handoff paths, I/O errors, EPOLLET/ONESHOT warnings, dispatches of
at least 1 ms, and callbacks of at least 1 ms are emitted. The existing
`--min-epoll-wait-us`, `--min-epoll-dispatch-us`, and
`--min-epoll-callback-us` options select custom thresholds and remain
available for advanced use. Explicit thresholds are mutually exclusive with
the three output-mode options.

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
unique callback-attachment, and attachment-failure counts. A separate
`libuv attribution coverage` block classifies every finished, resolvable
ready path by the strongest evidence Callweave actually observed:

- `exact`: the epoll ready event and a complete callback entry/return pair
  were both observed.
- `ready-to-I/O`: the callback boundary was unavailable, but the ready FD was
  correlated with a later read, write, receive, send, accept, or related I/O
  syscall and its user stack.
- `ready-only`: the FD became ready, but no complete callback or matching I/O
  was observed before that thread returned to epoll.

This classification is per ready path, so one capture can contain all three
levels. Callweave never promotes a fallback path to `exact`. In live text
output, dispatch and callback records include an `evidence` line. In JSON
Lines output, `epoll_dispatch` and `epoll_callback` records contain an
`evidence` field, while `epoll_summary` and `libuv_summary` contain the
coverage counters. Summary mode writes only the final summary records; select
`--live`, `--verbose`, or explicit thresholds when per-event JSON records are
needed. When a newly launched libuv process registers a poll
handle before its final epoll registration is visible, Callweave retries a
targeted `/proc/PID/fdinfo` lookup for that learned FD and seeds the normal
epoll token map without adding work to the BPF ready-event loop. Callback
rows use
the actual `uv_poll_t *` as their automatically learned key.
JSON Lines mode always emits the final `epoll_summary` and `libuv_summary`;
detail-enabled modes additionally emit the matching epoll and callback
records.

Matched native callbacks also inherit epoll callback futex attribution. A
slow `uv_poll_t` callback that waits on a contended pthread mutex reports the
futex address, longest wait, candidate waker thread, and waker stack. If the
blocked interval contains no supported futex wait, the report says so instead
of guessing a lock cause.

There are two deliberate boundaries in this first version:

- With `-p PID`, libuv handles whose `uv_poll_init/start` calls finished before
  attachment cannot be reconstructed safely from a stable public API. Generic
  epoll registrations are still recovered from `/proc/PID/fdinfo`, but
  automatic callback attribution begins with later libuv registrations.
  Earlier handles therefore remain observable through `ready-to-I/O` or
  `ready-only` evidence instead of disappearing from the report.
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
sudo ./callweave -p PID --libuv --live --epoll-top 5
```

The example writes to a nonblocking pipe every 50 ms and deliberately sleeps
for about 3 ms in every fifth poll callback, making the callback execution and
blocked-time attribution visible. It is also usable through `--exec`:

```sh
sudo ./callweave --libuv --duration 12 \
  --exec ./test/trace_libuv_test -- 20
```
