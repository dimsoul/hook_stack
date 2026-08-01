<!-- SPDX-License-Identifier: MIT -->

# Architecture

[Documentation index](README.md) · [Project README](../README.md)


The userspace loader attaches `trace_function` to the requested symbol.
When the uprobe fires, the BPF program records process metadata and calls
`bpf_get_stack(..., BPF_F_USER_STACK)`. With `--ret` or `--time`, it also stores
the entry timestamp in a per-thread nested-call state and attaches
`trace_function_return` as a uretprobe. The return probe pairs the
innermost outstanding call, reads the raw return register, and calculates the
elapsed monotonic time. With `--attribution`, raw scheduler switch and wakeup
tracepoints accumulate off-CPU, blocked, and run-queue intervals for every
active nested call. Raw syscall entry and exit tracepoints retain the longest
futex wait for the currently executing invocation. Wake operations are keyed
by process and futex address so the result can include the candidate wake
caller and its user stack. The loader consumes events, derives on-CPU time,
reads the
process's memory mappings, computes each ELF load bias from its `PT_LOAD`
segments, groups frames by module, and invokes `addr2line` without using a
shell. Async source probes store stack IDs and metadata in an LRU map keyed by
process and the selected argument. Intermediate target probes bind a consumed
lineage to the current thread until the target function returns, allowing a
later source call to inherit and extend it. Scheduler tracepoints attribute
each intermediate target's work before the next handoff. The final target
keeps the lineage until its return probe completes the last hop, then emits up
to eight hop descriptors. Userspace retrieves their producer stacks from a BPF
stack-trace map, symbolizes each segment, and prints a single completed causal
chain. In discovery mode, `sched_waking` records wakeups originating in the
selected process and keys the latest waker stack by target thread. Target
entry consumes that record so userspace can present a likely handoff site
without requiring the async source function in advance.
