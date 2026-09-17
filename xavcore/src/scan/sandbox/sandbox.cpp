#include "xavcore/scan/sandbox/sandbox.h"

#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <format>
#include <fstream>
#include <system_error>
#include <utility>

#include "seccomp_notifier.h"

namespace xavcore {
namespace {
// uid/gid the sandboxed process ends up with. Neither is mapped inside the
// sandbox' user namespace, so the kernel turns it into the overflow uid and the
// process is left without a single capability.
constexpr uid_t kSandboxUid = 65534;
constexpr gid_t kSandboxGid = 65534;

std::error_code last_error() { return {errno, std::system_category()}; }

outcome::result<void> write_file(const std::filesystem::path& path,
                                 const std::string& value) {
    std::ofstream file(path);
    if (!file) {
        return last_error();
    }
    file << value;
    if (!file) {
        return last_error();
    }
    return outcome::success();
}

bool is_mount_point(const std::filesystem::path& path) {
    struct stat self = {};
    struct stat parent = {};
    if (::stat(path.c_str(), &self) != 0) {
        return false;
    }
    auto parent_path = path / "..";
    if (::stat(parent_path.c_str(), &parent) != 0) {
        return false;
    }
    return self.st_dev != parent.st_dev;
}

// Close everything above the standard descriptors except `keep`, so the
// sandboxed process cannot reach any of the scanner's files or sockets.
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
    // Kernel without close_range(): fall back to the slow path below.
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

// Set up the namespaces and the filesystem view.  Runs in the child, before the
// target is forked, so the target inherits all of it.
outcome::result<void> enter_namespaces(const scan::sandbox::Config& config) {
    const uid_t uid = ::getuid();
    const gid_t gid = ::getgid();

    // The user namespace has to be created together with the others: it is what
    // gives us the privileges needed to create them, and those privileges are
    // scoped to the new namespace only.
    if (::unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS |
                  CLONE_NEWNET | CLONE_NEWCGROUP | CLONE_NEWPID) != 0) {
        return last_error();
    }

    // Map only our own uid and gid into the sandbox: being root inside it buys
    // nothing that we did not already have outside. An unprivileged gid map
    // requires setgroups() to be turned off first.
    if (auto result = write_file("/proc/self/setgroups", "deny"); !result) {
        return result;
    }
    if (auto result =
            write_file("/proc/self/uid_map", std::format("0 {} 1", uid));
        !result) {
        return result;
    }
    if (auto result =
            write_file("/proc/self/gid_map", std::format("0 {} 1", gid));
        !result) {
        return result;
    }

    // Nothing mounted in here may propagate back to the host.
    if (::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
        return last_error();
    }

    // The tmpfs is the only filesystem the sandboxed process can ever see.
    if (::chdir(config.rootfs.c_str()) != 0) {
        return last_error();
    }
    if (::chroot(".") != 0) {
        return last_error();
    }
    if (::chdir("/") != 0) {
        return last_error();
    }

    return outcome::success();
}

// Become the sandboxed process.  Never returns.
[[noreturn]] void launch_target(const std::filesystem::path& executable,
                                int handover) {
    ::prctl(PR_SET_PDEATHSIG, SIGKILL);

    // No exec may grant a privilege, and the uid swap below cannot be undone.
    ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    ::setresgid(kSandboxGid, kSandboxGid, kSandboxGid);
    ::setresuid(kSandboxUid, kSandboxUid, kSandboxUid);
    // No core dumps, no ptrace by anyone.
    ::prctl(PR_SET_DUMPABLE, 0);

    close_fds_except(handover);

    // From here on every syscall this process makes is reported to the
    // supervisor instead of running, so nothing at all reaches the kernel.
    // Failure is fatal on purpose: the target must never run unfiltered.
    if (!scan::sandbox::Supervisor::install_and_hand_over(handover)
             .has_value()) {
        exit_now(123);
    }

    char* const argv[] = {const_cast<char*>(executable.c_str()), nullptr};
    char* const envp[] = {nullptr};
    ::execve(executable.c_str(), argv, envp);

    // Reached when execve itself was refused, which is the normal case while
    // every syscall is denied.  Spinning in userspace is deliberate: asking for
    // anything else would only flood the notifier with syscalls that can never
    // succeed.  The supervisor kills this process when the run times out.
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

    outcome::result<void> prepare() {
        std::error_code ec;
        std::filesystem::create_directories(this->config_.rootfs, ec);
        if (ec) {
            return ec;
        }

        if (!is_mount_point(this->config_.rootfs)) {
            if (::mount("tmpfs", this->config_.rootfs.c_str(), "tmpfs",
                        MS_NOSUID | MS_NODEV,
                        this->config_.tmpfs_options.c_str()) != 0) {
                return last_error();
            }
        }

        return outcome::success();
    }

    outcome::result<SandboxRunResult> run(
        const std::filesystem::path& executable,
        ISandboxSyscallHandler& handler) {
        if (auto result = this->prepare(); !result) {
            return result.error();
        }

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
            // Intermediate process.  It sets the sandbox up and then forks the
            // real target, which is what makes the target pid 1 of the new pid
            // namespace (unshare(CLONE_NEWPID) only affects later children).
            ::close(handover[0]);
            ::prctl(PR_SET_PDEATHSIG, SIGKILL);

            if (auto result = enter_namespaces(this->config_); !result) {
                exit_now(125);
            }

            const pid_t target = ::fork();
            if (target < 0) {
                exit_now(124);
            }
            if (target == 0) {
                launch_target(executable, handover[1]);
            }

            ::close(handover[1]);
            int status = 0;
            while (::waitpid(target, &status, 0) < 0 && errno == EINTR) {
            }
            exit_now(WIFEXITED(status) ? WEXITSTATUS(status) : 126);
        }

        ::close(handover[1]);

        // Supervisor side: collect the notification fd, then answer syscalls
        // until the target is gone or the run times out.
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

        // Whatever is left inside the sandbox dies here, then reap the
        // intermediate process.
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

outcome::result<void> Sandbox::prepare() { return this->impl_->prepare(); }

outcome::result<SandboxRunResult> Sandbox::run(
    const std::filesystem::path& executable) {
    DenyAllSyscallHandler handler;
    return this->impl_->run(executable, handler);
}

outcome::result<SandboxRunResult> Sandbox::run(
    const std::filesystem::path& executable, ISandboxSyscallHandler& handler) {
    return this->impl_->run(executable, handler);
}
}  // namespace sandbox
}  // namespace scan
}  // namespace xavcore
