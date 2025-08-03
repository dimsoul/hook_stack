# hook_stack
`hook_stack` is a tool for tracing function call stacks in user-space applications using eBPF and uprobes.

## Overview

This project leverages eBPF (extended Berkeley Packet Filter) and uprobes to dynamically trace and record function call stacks in running processes. It is useful for debugging, performance analysis, and understanding program behavior without modifying the target application's source code.

## Prerequisites

- Linux kernel with BPF and BTF support (typically 5.4+)
- `clang` and `llvm` toolchain
- `bpftool`
- `libbpf` and `libelf` development libraries
- Sudo privileges (for some steps)

## Build and Usage Instructions

Follow these steps to build and run `hook_stack`:

1. **Generate the BTF Header**

    Export the kernel's BTF (BPF Type Format) information to a C header file. This is required for compiling the BPF program with correct type information.

    ```sh
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
    ```

2. **Compile the BPF Program**

    Use `clang` to compile the BPF source code into an object file suitable for loading into the kernel.

    ```sh
    clang -O2 -g -target bpf -c hook_stack.bpf.c -o hook_stack.bpf.o
    ```

3. **Generate the BPF Skeleton Header**

    Create a skeleton header from the compiled BPF object. This header simplifies loading and interacting with the BPF program from user space.

    ```sh
    sudo bpftool gen skeleton hook_stack.bpf.o > hook_stack.skel.h
    ```

4. **Build the User-Space Program**

    Compile the user-space application that loads and interacts with the BPF program.

    ```sh
    clang -g -o hook_stack hook_stack.c -lbpf -lelf
    ```

## Running hook_stack

After building, you can run the `hook_stack` binary to start tracing function call stacks. You may need root privileges depending on your tracing target and system configuration.

```sh
sudo ./hook_stack [options]
```

Refer to the source code or usage instructions within the program for available options and further details.

## Notes

- Ensure your kernel supports BPF and BTF.
- You may need to install additional development packages, such as `libbpf-dev` and `libelf-dev`.
- For more information on eBPF and uprobes, consult the official Linux documentation.
