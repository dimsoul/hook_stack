<!-- SPDX-License-Identifier: MIT -->

# epoll event-loop diagnostics

[Documentation index](../README.md) · [Project README](../../README.md)


Use standalone epoll mode to inspect event-loop wait behavior without knowing
a callback function in advance:

```sh
sudo ./callweave -p PID --epoll
sudo ./callweave -p PID --epoll --live --duration 10
sudo ./callweave -p PID --epoll --verbose --duration 10
```

The same output modes apply to generic epoll diagnostics. The default prints
the final aggregate report, `--live` streams slow and anomalous paths, and
`--verbose` streams every detail. For backward-compatible bounded event
capture, `--max-events` without an explicit mode implies verbose output;
it cannot be combined with `--summary-only` or `--live`.

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

## What epoll diagnostics help locate

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

## Callback execution attribution

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

When a matched callback blocks in a standard futex wait, Callweave also
records the futex address, operation, total wait time, longest wait, candidate
waker thread, and waker user stack. The final slow-callback section keeps the
futex information from the same invocation that established that callback
group's maximum duration, so the reported lock cause corresponds to the
displayed slowest callback rather than an unrelated aggregate sample:

```text
blocking in slowest callback:
  futex waits: count=1 total=25.121 ms
  longest futex: operation=wait address=0x... duration=25.121 ms
    waker PID 1234/TID 1236
    waker #0 libc.so.6 __GI___lll_lock_wake
    waker #1 server release_connection
```

`no futex wait observed` is a bounded result, not proof that the callback did
not block. Its blocked time may come from sleep, timers, I/O, or another wait
primitive. This version recognizes `FUTEX_WAIT` and `FUTEX_WAIT_BITSET`,
including their private variants after command-mask normalization.

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

## Wake-source attribution

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

## Anonymous kernel resources

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
sudo ./callweave -p PID --epoll --verbose --format json \
  --output ./callweave-epoll.jsonl
```

Without `--verbose`, `--live`, or custom thresholds, JSON mode writes only the
final `epoll_summary` (and `libuv_summary` in libuv mode).

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
