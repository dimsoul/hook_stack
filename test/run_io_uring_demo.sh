#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_file="$(mktemp)"
test_pid=

cleanup() {
    if [[ -n "${test_pid}" ]] && kill -0 "${test_pid}" 2>/dev/null; then
        kill "${test_pid}" 2>/dev/null || true
        wait "${test_pid}" 2>/dev/null || true
    fi
    rm -f "${output_file}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "${root_dir}"
./test/trace_io_uring_test 20 >"${output_file}" 2>&1 &
test_pid=$!

sleep 1
echo "Tracing io_uring test PID ${test_pid}"
sudo ./callweave -p "${test_pid}" --io-uring --duration 8 --max-events 4 \
    "$@"
wait "${test_pid}"
cat "${output_file}"
test_pid=
