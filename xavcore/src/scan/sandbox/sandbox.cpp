#include "xavcore/scan/sandbox/sandbox.h"

#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <system_error>

#include "seccomp_notifier.h"

namespace xavcore {
namespace {
std::error_code last_error() { return {errno, std::system_category()}; }

[[noreturn]] void exit_now(int code) {
    ::syscall(SYS_exit_group, code);
    for (;;) {
    }
}

// Become the sandboxed process. Never returns.
[[noreturn]] void run_target(const std::filesystem::path& executable,
                             int handover) {
    // Die if the supervisor dies.
    ::prctl(PR_SET_PDEATHSIG, SIGKILL);
    // Needed to load a seccomp filter without privileges.
    ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    // Install the filter and pass the notification fd to the supervisor. If
    // that fails, the target must not run at all, so exit.
    if (!scan::sandbox::Supervisor::install_and_hand_over(handover)
             .has_value()) {
        exit_now(123);
    }

    char* const argv[] = {const_cast<char*>(executable.c_str()), nullptr};
    char* const envp[] = {nullptr};
    ::execve(executable.c_str(), argv, envp);

    // execve is reported and denied too, so this is the normal path. Do not
    // make more syscalls here, each one would block on the supervisor. Just
    // spin until the supervisor kills this process.
    for (;;) {
    }
}
}  // namespace

namespace scan {
namespace sandbox {
SyscallResult DenyAllSyscallHandler::handle(const Syscall&) {
    return SyscallResult{.error = this->error_, .value = 0};
}

class Sandbox::Impl {
public:
    outcome::result<SandboxRunResult> run(
        const std::filesystem::path& executable,
        ISandboxSyscallHandler& handler) {
        int handover[2] = {-1, -1};
        if (::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, handover) != 0) {
            return last_error();
        }

        const pid_t child = ::fork();
        if (child < 0) {
            ::close(handover[0]);
            ::close(handover[1]);
            return last_error();
        }

        if (child == 0) {
            ::close(handover[0]);
            run_target(executable, handover[1]);
        }

        ::close(handover[1]);

        // Take the notification fd, then answer syscalls until the target is
        // gone.
        SandboxRunResult result;
        auto notify_fd = Supervisor::receive_fd(handover[0]);
        if (notify_fd.has_value()) {
            auto served = Supervisor::serve(notify_fd.value(), handler);
            if (served.has_value()) {
                result.intercepted_syscalls = served.value().answered;
            }
            ::close(notify_fd.value());
        }
        ::close(handover[0]);

        // Kill the target, then reap it. The kill matters when serve() failed
        // and the target is still blocked. It is not reaped before this point,
        // so its pid cannot be reused and the kill is safe.
        ::kill(child, SIGKILL);
        int status = 0;
        while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
        result.wait_status = status;

        if (!notify_fd.has_value()) {
            return notify_fd.error();
        }
        return result;
    }
};

Sandbox::Sandbox() : impl_(std::make_unique<Impl>()) {}

Sandbox::~Sandbox() = default;

outcome::result<SandboxRunResult> Sandbox::run(
    const std::filesystem::path& executable, ISandboxSyscallHandler& handler) {
    return this->impl_->run(executable, handler);
}
}  // namespace sandbox
}  // namespace scan
}  // namespace xavcore
