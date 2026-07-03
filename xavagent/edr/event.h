#pragma once

#include <optional>
#include <string>
#include <variant>

namespace xavagent {
struct FileEvent {
    enum class FileEventType {
        Create,
        Delete,
        Read,
        Write,
        Rename,
        Move,
        AttributeChange,
    };

    FileEventType event_type;

    // Who did the operation.
    int pid;
    std::string proc_path;

    // Who is(are) affected by the operation.
    std::string path1;
    std::optional<std::string> path2;
};

using Event = std::variant<FileEvent>;
}  // namespace xavagent
