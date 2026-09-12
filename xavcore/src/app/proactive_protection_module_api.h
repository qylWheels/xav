#include <cstdint>
namespace xavcore {
namespace app {
namespace proactive_protection_module_api {
struct StatusInfo {
    enum class Status {
        Running,
        Stopped,
    } status;

    std::uint64_t active_proc_count;
    std::uint64_t suspicious_proc_count;
    std::uint64_t malicious_proc_count;

    std::uint64_t event_count;
    std::uint64_t violate_rules_event_count;
};
}  // namespace proactive_protection_module_api
}  // namespace app
}  // namespace xavcore
