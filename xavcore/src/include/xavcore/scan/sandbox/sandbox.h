#pragma once

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <outcome.hpp>
#include <outcome/config.hpp>
#include <outcome/result.hpp>

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xavcore {
namespace scan {
namespace sandbox {
// A syscall made by the sandboxed process.
struct Syscall {
    // Notification id. Used to send the answer back.
    std::uint64_t id = 0;
    // Thread id of the caller, as seen in the sandbox.
    std::int32_t pid = 0;
    std::int32_t syscall_id = 0;
    std::uint64_t args[6] = {};
};

// The answer for one syscall.
struct SyscallResult {
    // Negative errno. 0 means success.
    int error = 0;
    // Return value. Only used when error is 0.
    std::int64_t value = 0;
};

// Decides how each syscall is answered.
class ISandboxSyscallHandler {
public:
    virtual ~ISandboxSyscallHandler() = default;

    virtual SyscallResult handle(const Syscall& syscall) = 0;
};

// Default handler. It fails every syscall, so no syscall reaches the kernel.
// Replace it once syscall emulation exists.
class DenyAllSyscallHandler : public ISandboxSyscallHandler {
public:
    explicit DenyAllSyscallHandler(int error = EPERM) : error_(error) {}

    SyscallResult handle(const Syscall& syscall) override;

private:
    int error_;
};

class Config {
public:
    // How long the sandboxed process may run before it is killed.
    std::chrono::milliseconds timeout{5000};
};

struct SandboxRunResult {
    // True when the run was stopped by the timeout instead of finishing.
    bool timed_out = false;
    // Number of syscalls the sandbox intercepted.
    std::uint64_t intercepted_syscalls = 0;
    // Raw wait status of the sandboxed process.
    int wait_status = 0;
};

// Runs an untrusted executable under a seccomp filter.
//
// The filter reports every syscall to this process. The handler decides the
// answer, and the syscall never reaches the kernel.
class Sandbox {
public:
    explicit Sandbox(Config config = {});
    ~Sandbox();
    Sandbox(const Sandbox&) = delete;
    Sandbox& operator=(const Sandbox&) = delete;
    Sandbox(Sandbox&&) = delete;
    Sandbox& operator=(Sandbox&&) = delete;

public:
    // Run `executable` with the default "deny every syscall" handler.
    outcome::result<SandboxRunResult> run(
        const std::filesystem::path& executable);

    // Same, with a caller supplied handler.
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
