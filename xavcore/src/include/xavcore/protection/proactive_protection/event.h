#pragma once

#include <unistd.h>

#include <bitset>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace xavcore {
struct Process {
    std::optional<std::uint32_t> pid;
    std::optional<std::uint32_t> ppid;
    std::optional<std::uint64_t> start_time_tick;
    std::optional<std::filesystem::path> exe_path;
    std::optional<std::string> cmdline;

    bool operator==(const Process& other) const {
        return pid == other.pid && start_time_tick == other.start_time_tick;
    }
};

#define FILE_EVENT_TYPE_MASK_SIZE 16

struct FileEvent {
    enum class FileEventType {
        Create,
        Delete,
        Read,
        Write,
        Move,
        AttributeChange,

        Count,
    };
    std::bitset<FILE_EVENT_TYPE_MASK_SIZE> event_type_mask;

    // Who did the operation.
    Process proc;

    // Who is(are) affected by the operation.
    std::string path1;
    std::optional<std::string> path2;

    // Attributes of files.
    std::optional<std::filesystem::file_status> stat1;
    std::optional<std::filesystem::file_status> stat2;
};

struct ReadSyscallEventPayload {
    int fd;
    std::optional<std::filesystem::path> path;
    void* buf;
    std::optional<std::vector<char>> buf_content;
    std::size_t count;
    ::ssize_t ret;
};

struct WriteSyscallEventPayload {
    int fd;
    std::optional<std::filesystem::path> path;
    const void* buf;
    std::optional<std::vector<char>> buf_content;
    std::size_t count;
    ::ssize_t ret;
};

struct UnlinkSyscallEventPayload {
    const char* pathname;
    std::optional<std::filesystem::path> path;
    int ret;
};

struct UnlinkatSyscallEventPayload {
    int dirfd;
    const char* pathname;
    std::optional<std::filesystem::path> path;
    int flags;
    int ret;
};

struct RenameSyscallEventPayload {
    const char* oldpath;
    std::optional<std::filesystem::path> oldpath_class;
    const char* newpath;
    std::optional<std::filesystem::path> newpath_class;
    int ret;
};

struct RenameatSyscallEventPayload {
    int olddirfd;
    const char* oldpath;
    std::optional<std::filesystem::path> oldpath_class;
    int newdirfd;
    const char* newpath;
    std::optional<std::filesystem::path> newpath_class;
    int ret;
};

struct Renameat2SyscallEventPayload {
    int olddirfd;
    const char* oldpath;
    std::optional<std::filesystem::path> oldpath_class;
    int newdirfd;
    const char* newpath;
    std::optional<std::filesystem::path> newpath_class;
    unsigned int flags;
    int ret;
};

struct ChmodSyscallEventPayload {
    const char* pathname;
    std::optional<std::filesystem::path> path;
    mode_t mode;
    int ret;
};

struct FchmodSyscallEventPayload {
    int fd;
    std::optional<std::filesystem::path> path;
    mode_t mode;
    int ret;
};

struct FchmodatSyscallEventPayload {
    int dirfd;
    const char* pathname;
    std::optional<std::filesystem::path> path;
    mode_t mode;
    int flags;
    int ret;
};

using SyscallEventPayload =
    std::variant<ReadSyscallEventPayload, WriteSyscallEventPayload,
                 UnlinkSyscallEventPayload, UnlinkatSyscallEventPayload,
                 RenameSyscallEventPayload, RenameatSyscallEventPayload,
                 Renameat2SyscallEventPayload, ChmodSyscallEventPayload,
                 FchmodSyscallEventPayload, FchmodatSyscallEventPayload>;

struct Event {
    Process process;
    std::variant<FileEvent, SyscallEventPayload> payload;
};
}  // namespace xavcore

namespace std {
template <>
struct hash<xavcore::Process> {
    std::size_t operator()(const xavcore::Process& p) const {
        std::size_t seed = std::hash<std::optional<std::int64_t>>{}(p.pid);
        if (p.start_time_tick.has_value()) {
            seed ^= std::hash<std::uint64_t>()(p.start_time_tick.value());
        }
        return seed;
    }
};
}  // namespace std
