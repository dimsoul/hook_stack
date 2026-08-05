// SPDX-License-Identifier: MIT

#ifndef CALLWEAVE_ASYNC_LIFECYCLE_H
#define CALLWEAVE_ASYNC_LIFECYCLE_H

enum cw_async_handoff_kind {
    CW_ASYNC_HANDOFF_NONE = 0,
    CW_ASYNC_HANDOFF_LIBUV = 1,
};

enum cw_async_lifecycle_flags {
    CW_ASYNC_LIFECYCLE_NOTIFY_ENTRY = 1U << 0,
    CW_ASYNC_LIFECYCLE_NOTIFY_EXIT = 1U << 1,
    CW_ASYNC_LIFECYCLE_EPOLL_EXIT = 1U << 2,
};

#endif
