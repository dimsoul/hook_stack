# SPDX-License-Identifier: MIT

CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
BPF_CPU ?= v3

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

LIBUV_CFLAGS := $(shell $(PKG_CONFIG) --cflags libuv 2>/dev/null)
LIBUV_LIBS := $(shell $(PKG_CONFIG) --libs libuv 2>/dev/null)
ifneq ($(strip $(LIBUV_LIBS)),)
LIBUV_DEFAULT_TARGETS = $(LIBUV_TEST_BINARY) $(LIBUV_WORK_TEST_BINARY)
endif

LIBEVENT_CFLAGS := $(shell $(PKG_CONFIG) --cflags libevent 2>/dev/null)
LIBEVENT_LIBS := $(shell $(PKG_CONFIG) --libs libevent 2>/dev/null)
ifneq ($(strip $(LIBEVENT_LIBS)),)
LIBEVENT_DEFAULT_TARGETS = $(LIBEVENT_TEST_BINARY) \
	$(LIBEVENT_BLOCKING_ACCEPT_TEST_BINARY)
endif

CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Wpedantic -Wno-overlength-strings
BPF_CFLAGS ?= -O2 -g
BPF_CFLAGS += -std=gnu11 -target bpf -mcpu=$(BPF_CPU) \
	-D__TARGET_ARCH_$(BPF_ARCH)

BINARY := callweave
TEST_BINARY := test/trace_test
ASYNC_TEST_BINARY := test/trace_async_test
THREAD_POOL_TEST_BINARY := test/trace_thread_pool_test
COMPLEX_ASYNC_TEST_BINARY := test/trace_complex_async_test
LOCK_TEST_BINARY := test/trace_lock_test
IO_URING_TEST_BINARY := test/trace_io_uring_test
EPOLL_TEST_BINARY := test/trace_epoll_test
LIBUV_TEST_BINARY := test/trace_libuv_test
LIBUV_WORK_TEST_BINARY := test/trace_libuv_work_test
LIBEVENT_TEST_BINARY := test/trace_libevent_test
LIBEVENT_BLOCKING_ACCEPT_TEST_BINARY := test/trace_libevent_blocking_accept
REPORT_TEST_BINARY := test/trace_report_test
BPF_OBJECT := src/callweave.bpf.o
VMLINUX_HEADER := src/vmlinux.h
SKELETON_HEADER := src/callweave.skel.h

.DELETE_ON_ERROR:
.PHONY: all clean test-program test-libuv test-libevent \
	demo-async demo-io-uring demo-epoll

all: $(BINARY) $(TEST_BINARY) $(ASYNC_TEST_BINARY) \
	$(THREAD_POOL_TEST_BINARY) $(COMPLEX_ASYNC_TEST_BINARY) \
	$(LOCK_TEST_BINARY) $(IO_URING_TEST_BINARY) $(EPOLL_TEST_BINARY) \
	$(REPORT_TEST_BINARY) $(LIBUV_DEFAULT_TARGETS) $(LIBEVENT_DEFAULT_TARGETS)

$(VMLINUX_HEADER):
	@test -r /sys/kernel/btf/vmlinux || \
		{ echo "error: /sys/kernel/btf/vmlinux is unavailable" >&2; exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJECT): src/callweave.bpf.c \
		src/core/core_config.h src/async/async_config.h \
		src/async/async_lifecycle.h \
		src/epoll/epoll_config.h src/epoll/epoll_shared.h \
		src/epoll/epoll.bpf.maps.h src/epoll/epoll.bpf.progs.h \
		src/epoll/epoll_wake.bpf.progs.h \
		src/epoll/epoll_callback.bpf.progs.h \
		src/libuv/libuv_shared.h \
		src/libuv/libuv.bpf.maps.h \
		src/libuv/libuv.bpf.progs.h \
		src/libevent/libevent_shared.h \
		src/libevent/libevent.bpf.maps.h \
		src/libevent/libevent.bpf.progs.h \
		src/io_uring/io_uring_config.h \
		src/io_uring/io_uring_shared.h \
		src/io_uring/io_uring.bpf.maps.h \
		src/io_uring/io_uring.bpf.progs.h \
		$(VMLINUX_HEADER)
	$(CLANG) $(BPF_CFLAGS) -Isrc -c $< -o $@

$(SKELETON_HEADER): $(BPF_OBJECT)
	$(BPFTOOL) gen skeleton $< > $@

$(BINARY): src/callweave.c src/core/capture_control.c \
		src/core/fd_resources.c \
		src/async/async_output.c src/config.c \
		src/epoll/epoll.c src/epoll/epoll_report.c \
		src/epoll/epoll_resources.c \
		src/libuv/libuv.c \
		src/libevent/libevent.c src/runtime/runtime_adapter.c \
		src/symbols.c src/io_uring/io_uring.c \
		src/io_uring/io_uring_report.c \
		src/io_uring/io_uring_resources.c \
		src/runtime_report.c src/runtime_report.h \
		src/io_uring/io_uring.h \
		src/io_uring/io_uring_internal.h \
		src/io_uring/io_uring_shared.h \
		src/async/async_config.h src/async/async_events.h \
		src/async/async_output.h \
		src/core/capture_control.h src/core/core_config.h \
		src/core/fd_resources.h \
		src/epoll/epoll.h src/epoll/epoll_internal.h \
		src/epoll/epoll_config.h src/epoll/epoll_shared.h \
		src/libuv/libuv.h src/libuv/libuv_shared.h \
		src/libevent/libevent.h src/libevent/libevent_shared.h \
		src/runtime/runtime_adapter.h \
		src/io_uring/io_uring_config.h \
		src/callweave_internal.h \
		src/config.h src/symbols.h \
		src/report.c src/report.h $(SKELETON_HEADER)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(LIBELF_CFLAGS) -Isrc \
		src/callweave.c src/core/capture_control.c \
		src/core/fd_resources.c \
		src/async/async_output.c src/config.c \
		src/epoll/epoll.c src/epoll/epoll_report.c \
		src/epoll/epoll_resources.c \
		src/libuv/libuv.c \
		src/libevent/libevent.c src/runtime/runtime_adapter.c \
		src/symbols.c src/io_uring/io_uring.c \
		src/io_uring/io_uring_report.c \
		src/io_uring/io_uring_resources.c src/report.c \
		src/runtime_report.c -o $@ \
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

$(IO_URING_TEST_BINARY): test/test_io_uring.c
	$(CC) -std=gnu11 -O0 -g -Wall -Wextra -fno-omit-frame-pointer \
		-fno-inline -rdynamic $< -o $@

$(EPOLL_TEST_BINARY): test/test_epoll.c
	$(CC) -std=gnu11 -O0 -g -Wall -Wextra -fno-omit-frame-pointer \
		-fno-inline -rdynamic $< -o $@ -pthread

$(REPORT_TEST_BINARY): test/test_report.c src/report.c src/report.h \
		src/runtime_report.c src/runtime_report.h
	$(CC) $(CFLAGS) -Isrc test/test_report.c src/report.c \
		src/runtime_report.c -o $@

$(LIBUV_TEST_BINARY): test/test_libuv.c
	@test -n "$(LIBUV_LIBS)" || \
		{ echo "error: libuv development files are required for test-libuv" >&2; \
		  echo "install libuv1-dev, then run make test-libuv" >&2; exit 1; }
	$(CC) -std=gnu11 -O0 -g -Wall -Wextra -fno-omit-frame-pointer \
		-fno-inline -rdynamic $(LIBUV_CFLAGS) $< -o $@ \
		$(LIBUV_LIBS) -pthread

test-libuv: $(LIBUV_TEST_BINARY)

$(LIBUV_WORK_TEST_BINARY): test/test_libuv_work.c
	@test -n "$(LIBUV_LIBS)" || \
		{ echo "error: libuv development files are required for test-libuv" >&2; \
		  echo "install libuv1-dev, then run make test-libuv" >&2; exit 1; }
	$(CC) -std=gnu11 -O0 -g -Wall -Wextra -fno-omit-frame-pointer \
		-fno-inline -rdynamic $(LIBUV_CFLAGS) $< -o $@ \
		$(LIBUV_LIBS) -pthread

test-libuv: $(LIBUV_WORK_TEST_BINARY)

$(LIBEVENT_TEST_BINARY): test/test_libevent.c
	@test -n "$(LIBEVENT_LIBS)" || \
		{ echo "error: libevent development files are required for test-libevent" >&2; \
		  echo "install libevent-dev, then run make test-libevent" >&2; exit 1; }
	$(CC) -std=gnu11 -O0 -g -Wall -Wextra -fno-omit-frame-pointer \
		-fno-inline -rdynamic $(LIBEVENT_CFLAGS) $< -o $@ \
		$(LIBEVENT_LIBS) -pthread

$(LIBEVENT_BLOCKING_ACCEPT_TEST_BINARY): test/test_libevent_blocking_accept.c
	@test -n "$(LIBEVENT_LIBS)" || \
		{ echo "error: libevent development files are required for test-libevent" >&2; \
		  echo "install libevent-dev, then run make test-libevent" >&2; exit 1; }
	$(CC) -std=gnu11 -O0 -g -Wall -Wextra -fno-omit-frame-pointer \
		-fno-inline -rdynamic $(LIBEVENT_CFLAGS) $< -o $@ \
		$(LIBEVENT_LIBS) -pthread

test-libevent: $(LIBEVENT_TEST_BINARY) \
	$(LIBEVENT_BLOCKING_ACCEPT_TEST_BINARY)

test-program: $(TEST_BINARY) $(ASYNC_TEST_BINARY) \
	$(THREAD_POOL_TEST_BINARY) $(COMPLEX_ASYNC_TEST_BINARY) \
	$(LOCK_TEST_BINARY) $(IO_URING_TEST_BINARY) $(EPOLL_TEST_BINARY) \
	$(REPORT_TEST_BINARY)

demo-async: all
	bash test/run_async_demo.sh

demo-io-uring: all
	bash test/run_io_uring_demo.sh

demo-epoll: all
	bash test/run_epoll_demo.sh

clean:
	rm -f $(BINARY) $(TEST_BINARY) $(ASYNC_TEST_BINARY) \
		$(THREAD_POOL_TEST_BINARY) $(COMPLEX_ASYNC_TEST_BINARY) \
		$(LOCK_TEST_BINARY) $(IO_URING_TEST_BINARY) \
		$(EPOLL_TEST_BINARY) $(REPORT_TEST_BINARY) $(BPF_OBJECT) \
		$(LIBUV_TEST_BINARY) $(LIBUV_WORK_TEST_BINARY) \
		$(LIBEVENT_TEST_BINARY) \
		$(LIBEVENT_BLOCKING_ACCEPT_TEST_BINARY) \
		$(VMLINUX_HEADER) \
		$(SKELETON_HEADER)
