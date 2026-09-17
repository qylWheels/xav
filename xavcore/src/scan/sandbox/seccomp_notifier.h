#pragma once

#include <chrono>
#include <cstdint>
#include <outcome.hpp>
#include <outcome/config.hpp>
#include <outcome/result.hpp>

#include "xavcore/scan/sandbox/sandbox.h"

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xavcore {
namespace scan {
namespace sandbox {
struct NotifyResult {
    // Number of syscalls answered.
    std::uint64_t answered = 0;
    // True when `serve()` stopped because the timeout fired.
    bool timed_out = false;
};

class Supervisor {
public:
    // Install, in the calling process, a filter whose default action is
    // SCMP_ACT_NOTIFY, hand its notification fd to the other end of
    // `handover_fd`, and release the libseccomp context.
    //
    // The order is forced by the mechanism: once the filter is loaded, every
    // syscall this process makes is reported to whoever holds the notification
    // fd, so the handover must be the very next thing that happens - the
    // supervisor does not exist until it has the fd.  sendmsg() on exactly
    // `handover_fd` is therefore the one syscall the filter allows.
    static outcome::result<void> install_and_hand_over(int handover_fd);

    // Receive the notification fd from the sandboxed process.
    static outcome::result<int> receive_fd(int sock,
                                           std::chrono::milliseconds timeout);

    // Answer the notifications arriving on `notify_fd` with `handler` until the
    // sandboxed process is gone or `timeout` expires.
    static outcome::result<NotifyResult> serve(
        int notify_fd, ISandboxSyscallHandler& handler,
        std::chrono::milliseconds timeout);

private:
    // Pass `fd` to the other end of `sock`.
    static outcome::result<void> send_fd(int sock, int fd);
};
}  // namespace sandbox
}  // namespace scan
}  // namespace xavcore
