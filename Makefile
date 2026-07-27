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

BINARY := callweave
TEST_BINARY := test/trace_test
ASYNC_TEST_BINARY := test/trace_async_test
THREAD_POOL_TEST_BINARY := test/trace_thread_pool_test
COMPLEX_ASYNC_TEST_BINARY := test/trace_complex_async_test
LOCK_TEST_BINARY := test/trace_lock_test
BPF_OBJECT := src/callweave.bpf.o
VMLINUX_HEADER := src/vmlinux.h
SKELETON_HEADER := src/callweave.skel.h

.DELETE_ON_ERROR:
.PHONY: all clean test-program demo-async

all: $(BINARY) $(TEST_BINARY) $(ASYNC_TEST_BINARY) \
	$(THREAD_POOL_TEST_BINARY) $(COMPLEX_ASYNC_TEST_BINARY) \
	$(LOCK_TEST_BINARY)

$(VMLINUX_HEADER):
	@test -r /sys/kernel/btf/vmlinux || \
		{ echo "error: /sys/kernel/btf/vmlinux is unavailable" >&2; exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJECT): src/callweave.bpf.c $(VMLINUX_HEADER)
	$(CLANG) $(BPF_CFLAGS) -Isrc -c $< -o $@

$(SKELETON_HEADER): $(BPF_OBJECT)
	$(BPFTOOL) gen skeleton $< > $@

$(BINARY): src/callweave.c src/report.c src/report.h $(SKELETON_HEADER)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(LIBELF_CFLAGS) -Isrc \
		src/callweave.c src/report.c -o $@ \
		$(LIBBPF_LIBS) $(LIBELF_LIBS) $(ZLIB_LIBS)

$(TEST_BINARY): test/test.c
	$(CC) -std=gnu11 -O0 -g -Wall -Wextra -fno-omit-frame-pointer -fno-inline \
		-rdynamic $< -o $@ -pthread

$(ASYNC_TEST_BINARY): test/test_async.c
	$(CC) -std=gnu11 -O0 -g -Wall -Wextra -fno-omit-frame-pointer -fno-inline \
		-rdynamic $< -o $@ -pthread

$(THREAD_POOL_TEST_BINARY): test/test_thread_pool.c
	$(CC) -std=gnu11 -O0 -g -Wall -Wextra -fno-omit-frame-pointer -fno-inline \
		-rdynamic $< -o $@ -pthread

$(COMPLEX_ASYNC_TEST_BINARY): test/test_complex_async.c
	$(CC) -std=gnu11 -O0 -g -Wall -Wextra -fno-omit-frame-pointer -fno-inline \
		-rdynamic $< -o $@ -pthread

$(LOCK_TEST_BINARY): test/test_lock.c
	$(CC) -std=gnu11 -O0 -g -Wall -Wextra -fno-omit-frame-pointer -fno-inline \
		-rdynamic $< -o $@ -pthread

test-program: $(TEST_BINARY) $(ASYNC_TEST_BINARY) \
	$(THREAD_POOL_TEST_BINARY) $(COMPLEX_ASYNC_TEST_BINARY) \
	$(LOCK_TEST_BINARY)

demo-async: all
	bash test/run_async_demo.sh

clean:
	rm -f $(BINARY) $(TEST_BINARY) $(ASYNC_TEST_BINARY) \
		$(THREAD_POOL_TEST_BINARY) $(COMPLEX_ASYNC_TEST_BINARY) \
		$(LOCK_TEST_BINARY) $(BPF_OBJECT) \
		$(VMLINUX_HEADER) \
		$(SKELETON_HEADER)
