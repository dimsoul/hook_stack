<!-- SPDX-License-Identifier: MIT -->

# Troubleshooting

[Documentation index](../README.md) · [Project README](../../README.md)


- **`failed to attach uprobe`**: verify the binary path and inspect symbols with
  `nm -an BINARY` or `readelf -Ws BINARY`.
- **`unable to collect user stack`**: ensure the architecture and kernel support
  user stack walking. Frame pointers and debug information improve results.
- **`?? at ??:0`**: the module is stripped, debug symbols are unavailable, or
  the mapped file was deleted after the process started.
- **`cannot read /proc/PID/maps`**: the process may have exited before the event
  was consumed. PID namespace translation is automatic; if it fails, the
  output also reports the kernel-global PID and the translation error.
- **Permission errors**: run as root or configure the required BPF and perf
  capabilities for your kernel and distribution.
- **Attribution tracepoint attachment fails**: verify that the kernel exposes
  the `sched_switch`, `sched_wakeup`, `sys_enter`, and `sys_exit` raw
  tracepoints and that the process has the required BPF/perf privileges.
  Discovery additionally uses `sched_waking`. Running as root is the simplest
  test.
- **No async origin is printed**: verify that both selected argument positions
  contain exactly the same nonzero pointer or integer value. Also check that
  the target runs before `--async-max-age-ms` expires. The context is
  intentionally consumed only once.
- **Discovery reports no waker stack**: make sure the target thread blocks and
  is subsequently woken while discovery is running. Kernel-originated wakeups
  may not have a useful user stack; stack walking also depends on kernel and
  architecture support.
- **Dropped events under heavy load**: the ring buffer is deliberately bounded.
  This tool is intended for targeted tracing rather than very hot functions.
