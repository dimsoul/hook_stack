# SPDX-License-Identifier: MIT

CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

ifndef BPF_ARCH
BPF_ARCH := $(shell uname -m)
BPF_ARCH := $(BPF_ARCH:x86_64=x86)
BPF_ARCH := $(BPF_ARCH:aarch64=arm64)
BPF_ARCH := $(BPF_ARCH:ppc64le=powerpc)
BPF_ARCH := $(BPF_ARCH:ppc64=powerpc)
BPF_ARCH := $(BPF_ARCH:mips64=mips)
BPF_ARCH := $(BPF_ARCH:riscv64=riscv)
BPF_ARCH := $(BPF_ARCH:s390x=s390)
endif

LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null)
ifeq ($(strip $(LIBBPF_LIBS)),)
LIBBPF_LIBS := -lbpf
endif

LIBELF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libelf 2>/dev/null)
LIBELF_LIBS := $(shell $(PKG_CONFIG) --libs libelf 2>/dev/null)
ifeq ($(strip $(LIBELF_LIBS)),)
LIBELF_LIBS := -lelf
endif

ZLIB_LIBS := $(shell $(PKG_CONFIG) --libs zlib 2>/dev/null)
ifeq ($(strip $(ZLIB_LIBS)),)
ZLIB_LIBS := -lz
endif

CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Wpedantic -Wno-overlength-strings
BPF_CFLAGS ?= -O2 -g
BPF_CFLAGS += -std=gnu11 -target bpf -D__TARGET_ARCH_$(BPF_ARCH)

BINARY := hook_stack
TEST_BINARY := test/trace_test
ASYNC_TEST_BINARY := test/trace_async_test
BPF_OBJECT := hook/hook_stack.bpf.o
VMLINUX_HEADER := hook/vmlinux.h
SKELETON_HEADER := hook/hook_stack.skel.h

.DELETE_ON_ERROR:
.PHONY: all clean test-program

all: $(BINARY) $(TEST_BINARY) $(ASYNC_TEST_BINARY)

$(VMLINUX_HEADER):
	@test -r /sys/kernel/btf/vmlinux || \
		{ echo "error: /sys/kernel/btf/vmlinux is unavailable" >&2; exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJECT): hook/hook_stack.bpf.c $(VMLINUX_HEADER)
	$(CLANG) $(BPF_CFLAGS) -Ihook -c $< -o $@

$(SKELETON_HEADER): $(BPF_OBJECT)
	$(BPFTOOL) gen skeleton $< > $@

$(BINARY): hook/hook_stack.c $(SKELETON_HEADER)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(LIBELF_CFLAGS) -Ihook $< -o $@ \
		$(LIBBPF_LIBS) $(LIBELF_LIBS) $(ZLIB_LIBS)

$(TEST_BINARY): test/test.c
	$(CC) -std=gnu11 -O0 -g -Wall -Wextra -fno-omit-frame-pointer -fno-inline \
		-rdynamic $< -o $@ -pthread

$(ASYNC_TEST_BINARY): test/test_async.c
	$(CC) -std=gnu11 -O0 -g -Wall -Wextra -fno-omit-frame-pointer -fno-inline \
		-rdynamic $< -o $@ -pthread

test-program: $(TEST_BINARY) $(ASYNC_TEST_BINARY)

clean:
	rm -f $(BINARY) $(TEST_BINARY) $(ASYNC_TEST_BINARY) $(BPF_OBJECT) \
		$(VMLINUX_HEADER) \
		$(SKELETON_HEADER)
