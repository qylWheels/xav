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
    // True when serve() stopped because of the timeout.
    bool timed_out = false;
};

// The supervisor side of seccomp user notification.
class Supervisor {
public:
    // Install a filter whose default action is SCMP_ACT_NOTIFY, send the
    // notification fd to the supervisor, then release the filter context.
    //
    // Order matters. After the filter is loaded, every syscall of this process
    // is reported and only the supervisor can answer it. So the fd is sent
    // first. The filter allows sendmsg() on the hand-over socket, or that send
    // would block forever.
    static outcome::result<void> install_and_hand_over(int handover_fd);

    // Receive the notification fd from the sandboxed process.
    static outcome::result<int> receive_fd(int sock,
                                           std::chrono::milliseconds timeout);

    // Answer notifications with `handler` until the sandboxed process is gone
    // or `timeout` expires.
    static outcome::result<NotifyResult> serve(
        int notify_fd, ISandboxSyscallHandler& handler,
        std::chrono::milliseconds timeout);

private:
    // Send `fd` to the other end of `sock`.
    static outcome::result<void> send_fd(int sock, int fd);
};
}  // namespace sandbox
}  // namespace scan
}  // namespace xavcore
