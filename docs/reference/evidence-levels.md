<!-- SPDX-License-Identifier: MIT -->

# Evidence levels

[Documentation index](../README.md) · [Project README](../../README.md)

Callweave reports the strongest causal evidence actually observed for each resolvable epoll-ready path. It does not promote a fallback correlation to an exact callback match.

| Level | Required observation | Interpretation |
| --- | --- | --- |
| `exact` | epoll readiness plus a matched callback entry and return | The selected runtime or callback adapter observed the complete handler boundary. |
| `ready-to-I/O` | epoll readiness plus a matching read, write, receive, send, accept, or related I/O syscall | The callback boundary was unavailable, but the ready FD was handled by the observed thread and I/O stack. |
| `ready-only` | epoll readiness without a completed callback or matching I/O before the next wait | The FD became ready, but Callweave cannot claim which handler consumed it. |

The final `epoll_summary` and `libuv_summary` report coverage counts for all three levels. Text dispatch and callback records include an `evidence` line; JSON detail records include an `evidence` field.

Late attachment can reduce evidence strength because callback initialization or registration may have completed before Callweave attached. Generic epoll registration recovery and libuv FD learning preserve fallback attribution where possible, but activity that completed before attachment cannot be reconstructed.

See [epoll diagnostics](../features/epoll.md) and the [libuv adapter](../runtimes/libuv.md) for mode-specific boundaries.
