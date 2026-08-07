#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>

namespace xavcore {
class IRule {
public:
    virtual ~IRule() = default;

public:
    // The name of the rule.
    virtual std::string name() = 0;

    // Whether the rule is enabled.
    virtual bool enabled() = 0;

    // Whether to allow the event to happen.
    virtual bool allow() = 0;

    // Whether to kill the process.
    virtual bool kill_process() = 0;

    // The lower the value, the higher the priority of the rule.
    virtual std::uint16_t priority() = 0;

    // Who triggers the rule.
    virtual std::filesystem::path trigger() = 0;
};

class IFileRule : public IRule {
public:
    virtual ~IFileRule() = default;

public:
    enum class EventType : std::uint16_t {
        Create = 1 << 0,
        Delete = 1 << 1,
        Read = 1 << 2,
        Write = 1 << 3,
        Execute = 1 << 4,
    };

public:
    // The event type of the rule.
    virtual EventType event_type() = 0;

    // The path of the file.
    virtual std::filesystem::path path() = 0;
};

class IRuleGroup {
public:
    virtual ~IRuleGroup() = default;

public:
    // The name of the rule group.
    virtual std::string name() = 0;

    // Add a rule to the group.
    virtual void add_rule(IRule& rule) = 0;

    // Remove a rule from the group.
    virtual void remove_rule(IRule& rule) = 0;

    // Get all rules in the group.
    virtual std::span<IRule*> all_rules() = 0;
};
}  // namespace xavcore
