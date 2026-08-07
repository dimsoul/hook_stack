<!-- SPDX-License-Identifier: MIT -->

# libevent: a client connection stops timer callbacks

[Documentation index](../README.md) | [Project README](../../README.md)

## Reported symptom

A real Stack Overflow report describes a libevent server whose periodic timer
works normally until the first client connects. After the listener event fires,
the timer stops. From that symptom alone it is unclear whether the connection
was delivered late, libevent delayed dispatch, or an application callback kept
the event-loop thread occupied.

The original report is:
[My libevent timer stops as soon as another event occurs](https://stackoverflow.com/questions/33184319/my-libevent-timer-stops-as-soon-as-another-event-occurs-is-that-normal).
The reporter later identified a blocking listening socket as the cause.

## Diagnostic reconstruction

The public report links a much larger application rather than a standalone
reproducer, so `test/test_libevent_blocking_accept.c` reconstructs the
same mechanism:

- one persistent libevent timer fires every 200 ms;
- one persistent read event watches a TCP listening socket;
- the listening socket is intentionally left in blocking mode;
- the listener callback calls `accept()` again after consuming the first
  pending connection;
- a second client connects 1.5 seconds later so that the blocked callback can
  return and produce a complete timing record.

Build the bundled reproducer and other libevent test target with:

```sh
make test-libevent
```

Callweave launched the target from startup so that libevent event definitions,
epoll registrations, and dynamically discovered application callbacks were all
observed:

```sh
sudo ./callweave --libevent --duration 5 \
  --exec ./test/trace_libevent_blocking_accept -- --blocking
```

## Evidence

The listener FD became ready and libevent entered the application callback
almost immediately:

```text
listener FD ready
  -> accept_cb entry       18.111 us
  -> accept_cb execution    1.501 s
       on-CPU                 110.556 us
       blocked                  1.500 s
       run queue                   3.937 us
```

The path had `exact` evidence: the same ready listening FD was joined to a
complete callback entry and return. The first I/O stack from that callback was:

```text
accept_cb
  -> accept
```

During the 1.5-second callback interval no timer callback ran. The event loop
was not waiting in `epoll_wait`, and it was not consuming CPU; it was blocked
inside the listener callback.

A nonblocking control run kept the same event, clients, and timer. Its two
listener callbacks had a maximum execution time of 64.451 us, zero observed
blocked time, and the timer continued without a gap. This control distinguishes
the blocking callback from network arrival or libevent dispatch latency.

Run that control with:

```sh
sudo ./callweave --libevent --duration 5 \
  --exec ./test/trace_libevent_blocking_accept -- --nonblocking
```

## Diagnosis

The listening socket is blocking. After the callback accepts the connection
that made the FD ready, another `accept()` waits for a future connection instead
of returning control to libevent. Because the listener callback runs on the
event-loop thread, timer callbacks and all other events remain pending until
that blocking `accept()` returns.

Callweave therefore localizes the failure to the application boundary:

```text
epoll readiness and libevent dispatch: normal
listener callback: blocked in accept()
missing timer callbacks: downstream consequence
```

No CPU profile or version bisect is required for this conclusion.
