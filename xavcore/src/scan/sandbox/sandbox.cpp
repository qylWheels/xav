#include "xavcore/scan/sandbox/sandbox.h"

#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <system_error>
#include <utility>

#include "seccomp_notifier.h"

namespace xavcore {
namespace {
std::error_code last_error() { return {errno, std::system_category()}; }

// Close every fd above the standard ones, except `keep`. The target must not
// inherit the scanner's files or sockets.
void close_fds_except(int keep) {
#ifdef SYS_close_range
    bool closed = true;
    if (keep > 3) {
        closed = ::syscall(SYS_close_range, 3u,
                           static_cast<unsigned int>(keep - 1), 0u) == 0;
    }
    if (closed) {
        closed = ::syscall(SYS_close_range, static_cast<unsigned int>(keep + 1),
                           ~0u, 0u) == 0;
    }
    if (closed) {
        return;
    }
    // No close_range() on this kernel. Use the loop below.
#endif
    long limit = ::sysconf(_SC_OPEN_MAX);
    if (limit < 0 || limit > 65536) {
        limit = 65536;
    }
    for (int fd = 3; fd < limit; ++fd) {
        if (fd != keep) {
            ::close(fd);
        }
    }
}

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

    close_fds_except(handover);

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
    // spin until the supervisor kills this process on timeout.
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
    explicit Impl(Config config) : config_(std::move(config)) {}

    outcome::result<SandboxRunResult> run(
        const std::filesystem::path& executable,
        ISandboxSyscallHandler& handler) {
        const auto deadline =
            std::chrono::steady_clock::now() + this->config_.timeout;
        auto remaining = [&deadline] {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());
        };

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
        // gone or the timeout expires.
        SandboxRunResult result;
        auto notify_fd = Supervisor::receive_fd(handover[0], remaining());
        if (notify_fd.has_value()) {
            auto served =
                Supervisor::serve(notify_fd.value(), handler, remaining());
            if (served.has_value()) {
                result.timed_out = served.value().timed_out;
                result.intercepted_syscalls = served.value().answered;
            }
            ::close(notify_fd.value());
        }
        ::close(handover[0]);

        // Kill the target, then reap it. It is not reaped before this point, so
        // its pid cannot be reused and the kill is safe.
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

private:
    Config config_;
};

Sandbox::Sandbox(Config config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

Sandbox::~Sandbox() = default;

outcome::result<SandboxRunResult> Sandbox::run(
    const std::filesystem::path& executable, ISandboxSyscallHandler& handler) {
    return this->impl_->run(executable, handler);
}
}  // namespace sandbox
}  // namespace scan
}  // namespace xavcore
