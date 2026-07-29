#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_file="$(mktemp)"
test_pid=
target_args=()
tracer_args=()
attach_delay=1

for argument in "$@"; do
    if [[ "${argument}" == "--bad-et" ||
          "${argument}" == "--bad-oneshot" ||
          "${argument}" == "--multi-waiter" ||
          "${argument}" == "--fd-reuse" ]]; then
        target_args+=("${argument}")
    elif [[ "${argument}" == "--late-attach" ]]; then
        attach_delay=3
    else
        tracer_args+=("${argument}")
    fi
done

cleanup()
{
    if [[ -n "${test_pid}" ]] &&
       kill -0 "${test_pid}" 2>/dev/null; then
        kill "${test_pid}" 2>/dev/null || true
        wait "${test_pid}" 2>/dev/null || true
    fi
    rm -f "${output_file}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "${root_dir}"
./test/trace_epoll_test "${target_args[@]}" >"${output_file}" 2>&1 &
test_pid=$!

sleep "${attach_delay}"
if [[ "${attach_delay}" -gt 1 ]]; then
    echo "Late-attaching after existing epoll registrations"
fi
echo "Tracing epoll test PID ${test_pid}"
sudo ./callweave -p "${test_pid}" --epoll --duration 8 \
    --min-epoll-wait-us 1000 --epoll-top 3 "${tracer_args[@]}"
kill -TERM "${test_pid}" 2>/dev/null || true
wait "${test_pid}"
cat "${output_file}"
test_pid=
