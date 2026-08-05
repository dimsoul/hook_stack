<!-- SPDX-License-Identifier: MIT -->

# libevent runtime adapter

[Documentation index](../README.md) | [Project README](../../README.md)

The libevent adapter observes stable public APIs rather than private libevent
structure layouts. It covers three application-facing object families:

- raw events through `event_new`, `event_assign`, `event_add`, `event_del`,
  and `event_free`;
- socket bufferevents through `bufferevent_socket_new`, `bufferevent_setcb`,
  `bufferevent_setfd`, `bufferevent_enable`, `bufferevent_disable`, and
  `bufferevent_free`;
- listeners created from an existing FD through `evconnlistener_new` and
  `evconnlistener_free`.

From those APIs it learns:

```text
raw event / bufferevent / listener object -> FD -> callback role and address
```

When a callback address is discovered, Callweave resolves its file-backed ELF
mapping and dynamically attaches callback entry and return uprobes. For I/O
events, the epoll backend connects readiness to the callback's first argument
(`evutil_socket_t fd`). For bufferevents and listeners it instead resolves the
object pointer passed to the callback back to the learned FD. Both paths report
ready-to-callback delay, callback duration, scheduler attribution, resource
identity, and callback stacks.

No event pointer, callback name, FD, callback argument position, or
`epoll_event.data` value is required:

```sh
sudo ./callweave -p PID --libevent
sudo ./callweave -p PID --libevent --live --duration 20
```

For the smallest startup blind window, let Callweave launch the target after
the BPF programs and runtime API probes are ready:

```sh
sudo ./callweave --libevent --duration 20 \
  --exec ./server -- --port 8080
```

The ELF defining `event_add` is normally found automatically among mapped
modules for `-p PID`, or among dynamic dependencies in `--exec` mode. Override
the module only for an unusual loader layout, a later `dlopen`, or a bundled
copy that cannot be inferred:

```sh
sudo ./callweave -p PID --libevent \
  --libevent-binary /opt/application/lib/libevent_core.so.2
```

## Event types and evidence

The adapter classifies raw definitions as I/O, timer, signal, or unsupported:

- I/O events have `EV_READ` or `EV_WRITE` and a nonnegative application FD.
  They can produce `exact`, `ready-to-I/O`, or `ready-only` evidence.
- Timer events are counted in adapter health. A libevent timeout does not
  identify an application I/O FD, so it is not promoted to an exact epoll
  callback path.
- Signal events are also counted separately. libevent may dispatch them via
  internal notification resources, but the callback's first argument is a
  signal number rather than the internal epoll FD.
- Persistent I/O events use the same correlation model as one-shot I/O events;
  every completed callback can match a separate ready path.
- Bufferevent read, write, and status callbacks are classified by role. Only
  callbacks whose object currently has a valid socket FD can be joined to an
  epoll-ready path.
- Existing-FD listener accept callbacks are joined through the listener object
  passed as callback argument 1.

`exact` still means that both the kernel-ready event and a complete callback
entry/return pair were observed. Callweave does not infer exact causality from
an event definition alone.

## Output

The default is a final aggregate `libevent summary`. `--live` emits slow or
anomalous paths, while `--verbose` emits every collected detail. The backend
summary retains epoll wait, resource, wake-source, ET/ONESHOT, and dispatch
diagnostics. The additional adapter sections report:

- created, assigned, added, deleted, and freed event counts;
- I/O, timer, signal, and unsupported event counts, split by persistent and
  one-shot trigger policy;
- registration ring-buffer events and drops;
- unique application callbacks, libevent-internal callbacks, successfully
  attached callbacks, and attachment failures;
- bufferevent create/setcb/setfd/enable/disable/free activity;
- existing-FD listener create/free activity;
- `event_add` calls whose definitions were created before tracing began;
- exact/fallback attribution coverage and targeted FD seed results.

For every matched raw-event, bufferevent, or listener callback, the shared
epoll callback tracer also attributes standard futex waits. Live output and
the slowest-callback summary show the futex address, longest wait, candidate
waker thread, and waker stack. A callback with blocked scheduler time but no
supported futex wait is explicitly labeled as a possible sleep, timer, I/O,
or other wait rather than being misdiagnosed as lock contention.

JSON Lines output contains the normal `epoll_summary` plus a
`libevent_summary` record. Per-event records require `--live`, `--verbose`, or
explicit `--min-epoll-*-us` thresholds.

## Field glossary

- `unmatched callback` means a callback entry could not be joined to an
  epoll-ready application FD. This is not automatically an error: timer and
  signal callbacks are expected here because their first argument is not an
  application I/O FD. It is separate from dropped records.
- `pending final cycle` means the capture ended while a ready path was still
  open. A target that exits directly from its last callback commonly leaves
  one such cycle because there is no next `epoll_wait` boundary to finalize
  it. It is not counted as dropped data.
- `stale FD lifetime` marks a historical FD generation retained after the FD
  was closed or reused. Generation tracking prevents it from being confused
  with a later resource that receives the same numeric FD.
- `unique-user`, `runtime-internal`, and `instrumented` count distinct
  application callbacks, callbacks whose implementation resides inside the
  libevent module, and application callbacks that received entry/return
  probes, respectively.
- `setfd` counts successful `bufferevent_setfd()` calls only. Zero is normal
  when the socket FD was supplied to `bufferevent_socket_new()`.
- `high-level discovery` counts emitted bufferevent/listener callback-state
  records. It is not the number of callback invocations; invocation totals are
  shown in the callback execution table.

## Boundaries

- With `-p PID`, completed `event_new/event_assign` calls cannot be recovered
  from a stable public API. Generic epoll registrations are still bootstrapped
  from `/proc/PID/fdinfo`, while automatic callback attribution begins with
  definitions or activations observed after attach. Prefer `--exec` when
  startup coverage matters.
- Dynamic callback attachment requires an application callback in a file-backed executable
  mapping. Native C/C++ callbacks work even without symbol names; JIT-only
  callbacks need a runtime-specific symbol source.
- Callbacks whose code resides inside the libevent module are counted as
  runtime-internal callbacks and are not instrumented as application work.
- Timer and signal events are visible in lifecycle health but intentionally are
  not mapped to an unrelated internal backend FD.
- `evconnlistener_new_bind` does not expose a stable existing FD at the public
  API boundary, so it is not promoted to exact listener attribution. Use
  `evconnlistener_new` with an already-created nonblocking listening FD when
  exact listener callback attribution is required.

## Test

Install the optional development package and build the example:

```sh
sudo apt install libevent-dev
make test-libevent
```

Two-terminal test:

```sh
# Terminal 1: prints its PID and waits before creating events.
./test/trace_libevent_test --iterations 100 --lock-contention

# Terminal 2
sudo ./callweave -p PID --libevent --live --epoll-top 5
```

Complete-from-start test:

```sh
sudo ./callweave --libevent --live --duration 12 \
  --report ./callweave-libevent.html \
  --exec ./test/trace_libevent_test -- \
  --startup-delay 0 --iterations 80
```

The HTML Sequence view uses real thread lanes. `epoll_wait*`, readiness
dispatch, and the automatically discovered callback remain vertical phases on
the libevent-loop thread; a producer lane appears only for an observed
cross-thread wake. It distinguishes time blocked in `epoll_wait*`,
ready-to-callback dispatch delay, and callback
execution even though the event loop and callback normally share one TID;
futex attribution remains available in Waterfall and Details. Callback lanes
combine the runtime role and resolved ELF symbol, such as
`libevent_callback (socket_ready_callback)` or
`libevent_callback (bufferevent_read_callback)`. When no symbol is available
the parenthesized value is `callback@0xADDRESS`, which remains distinct for
each callback address.

The Sequence card calls the combined producer-to-ready and ready-to-callback
portion `Selected pre-callback`. Its violet dispatch label is written as
`ready → CALLBACK` followed by `pre-callback dispatch · DURATION`; the blue
phase repeats the full resolved callback name and its execution duration.
Long names remain available in full in the lane header and SVG hover text.

When Callweave observes the example's `socketpair()` creation from startup, it
also correlates the writer thread's `send()` with readiness of the peer FD.
The Sequence view then contains separate writer and libevent-loop TID lanes,
with `send → epoll_wait*` as the cross-thread handoff. This correlation is why
the complete-from-start `--exec` test is preferred; attaching after the
socketpair already exists cannot recover its peer relationship.

The example exercises a persistent Unix-socket raw event, a socket
bufferevent, an existing-FD listener, and a persistent timer. Every tenth I/O
callback deliberately runs longer so callback latency and scheduler
attribution are visible. The listener FD is nonblocking, as required by
`evconnlistener_new`. With `--lock-contention`, the writer holds a mutex while
every tenth raw callback tries to acquire it, producing a deterministic futex
waker example.
