#pragma once

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <outcome.hpp>
#include <outcome/config.hpp>
#include <outcome/result.hpp>
#include <string>

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xavcore {
namespace scan {
namespace sandbox {
// Syscall invoked by process in sandbox.
struct Syscall {
    // Notification id, needed to answer this request.
    std::uint64_t id = 0;
    // Thread id of the caller, as seen inside the sandbox.
    std::int32_t pid = 0;
    std::int32_t syscall_id = 0;
    std::uint64_t args[6] = {};
};

// How the sandbox answers a syscall.
struct SyscallResult {
    // Negative errno, 0 for success.
    int error = 0;
    // Return value, used only when `error` is 0.
    std::int64_t value = 0;
};

// Decides what happens to every syscall the sandboxed process makes.
class ISandboxSyscallHandler {
public:
    virtual ~ISandboxSyscallHandler() = default;

    virtual SyscallResult handle(const Syscall& syscall) = 0;
};

// The handler used until syscall emulation exists: every syscall is failed, so
// nothing the sandboxed process asks for can reach the kernel.
class DenyAllSyscallHandler : public ISandboxSyscallHandler {
public:
    explicit DenyAllSyscallHandler(int error = EPERM) : error_(error) {}

    SyscallResult handle(const Syscall& syscall) override;

private:
    int error_;
};

class Config {
public:
    // Directory the tmpfs that becomes the sandboxed process' "/" is mounted
    // on. Populate it between prepare() and run().
    std::filesystem::path rootfs = "/run/xavcore/sandbox-rootfs";
    std::string tmpfs_options = "size=64m,mode=0755";

    // How long the sandboxed process may run before it is killed.
    std::chrono::milliseconds timeout{5000};
};

struct SandboxRunResult {
    // True when the run was stopped after `timeout` instead of finishing.
    bool timed_out = false;
    // Number of syscalls the sandbox intercepted.
    std::uint64_t intercepted_syscalls = 0;
    // Raw wait status of the sandboxed process.
    int wait_status = 0;
};

// Runs an untrusted executable inside a isolated environment:
//
//   * user, mount, pid, network, ipc, uts and cgroup namespaces, so the process
//     has no view of, and no privileges over, the host;
//   * a tmpfs mounted as its root filesystem, so nothing it writes survives;
//   * a seccomp filter that reports every syscall to this process instead of
//     letting it run, so nothing reaches the kernel.
class Sandbox {
public:
    explicit Sandbox(Config config = {});
    ~Sandbox();
    Sandbox(const Sandbox&) = delete;
    Sandbox& operator=(const Sandbox&) = delete;
    Sandbox(Sandbox&&) = delete;
    Sandbox& operator=(Sandbox&&) = delete;

public:
    // Mount the tmpfs root and create the cgroup. Idempotent.
    outcome::result<void> prepare();

    // Run `executable`, a path inside the sandbox root, with the default
    // "deny every syscall" handler.
    outcome::result<SandboxRunResult> run(
        const std::filesystem::path& executable);

    // Same, with a caller supplied syscall handler.
    outcome::result<SandboxRunResult> run(
        const std::filesystem::path& executable,
        ISandboxSyscallHandler& handler);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
}  // namespace sandbox
}  // namespace scan

}  // namespace xavcore
