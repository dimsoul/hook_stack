<!-- SPDX-License-Identifier: MIT -->

# Callweave documentation

[Project README](../README.md)

## Start here

- [Getting started](getting-started.md): dependencies, build, and source layout.
- [Testing guide](testing.md): commands for the bundled examples and failure scenarios.
- [Release guide](releasing.md): version tags, automated multi-architecture packaging, and checksums.
- [CLI reference](reference/cli-options.md): command forms, output modes, and option groups.
- [Troubleshooting](troubleshooting/common-issues.md): common attachment, symbol, permission, and event-loss problems.

## Core features

- [Function tracing and scheduler attribution](features/function-tracing.md)
- [Asynchronous call-chain tracing](features/async-call-chain.md)
- [Queue and thread-pool diagnostics](features/queue-diagnostics.md)
- [epoll event-loop diagnostics](features/epoll.md)
- [io_uring request diagnostics](features/io-uring.md)

## Runtime adapters

- [libuv](runtimes/libuv.md): automatic `uv_poll_t` handle, FD, and callback correlation.
- [libevent](runtimes/libevent.md): automatic event lifecycle, I/O FD, and callback correlation.

Runtime-specific behavior belongs under `docs/runtimes/`. A future adapter such as Boost.Asio should add one document here instead of extending the project README.

## Case studies

- [libuv: delayed `after_work_cb`](cases/libuv-work-callback-delay.md):
  distinguish worker-pool queueing, worker execution, and event-loop delay.
- [libevent: a client connection stops timer callbacks](cases/libevent-blocking-accept.md):
  identify the listener callback blocked in `accept()` while timers remain pending.
- [libuv: slow DNS stalls unrelated serial work](cases/libuv-dns-threadpool-contention.md):
  localize a multi-second serial delay to queueing behind DNS in libuv's shared worker pool.

## Output and interpretation

- [JSON and HTML output](output/reports.md)
- [Evidence levels](reference/evidence-levels.md)

## Internals

- [Architecture](architecture.md)
