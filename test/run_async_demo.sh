#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

if [[ ! -x ./callweave || ! -x ./test/trace_thread_pool_test ]]; then
    echo "error: build the project first with 'make'" >&2
    exit 1
fi

target_log="${TMPDIR:-/tmp}/callweave-thread-pool-demo.log"
./test/trace_thread_pool_test >"$target_log" 2>&1 &
target_pid=$!

cleanup() {
    kill "$target_pid" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        kill -0 "$target_pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -KILL "$target_pid" 2>/dev/null || true
    wait "$target_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

sleep 1
sudo ./callweave -p "$target_pid" \
    --async-hop submit_compute_task,2,process_request,1 \
    --async-hop submit_storage_task,2,write_result,1 \
    write_result
