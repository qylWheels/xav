#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <boost/asio.hpp>
#include <cpptrace/cpptrace.hpp>
#include <csignal>
#include <functional>
#include <iostream>

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_based_detection_listener.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/anti_debug_rule.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/aslr_inspection_rule.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/cgroup_notify_on_release_rule.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/cgroup_release_agent_rule.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/core_pattern_modification_rule.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/default_loader_modify_rule.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/dynamic_code_loading_rule.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/fileless_execution_rule.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/hidden_file_rule.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/kernel_module_loading_rule.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/proc_kcore_read_rule.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/proc_mem_access_rule.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/process_vm_inject_rule.h"
#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event_provider.h"

namespace asio = boost::asio;

void startup(spdlog::logger& logger) {
    // I/O context.
    asio::io_context ioc;

    // Endpoint.
    std::string socket_path =
        std::string("\0", 1) + "xavcore_proactive_protection_module_socket";
    asio::local::seq_packet_protocol::endpoint ep(socket_path);

    // Acceptor.
    asio::local::seq_packet_protocol::acceptor acceptor(ioc, ep);

    // Socket.
    asio::local::seq_packet_protocol::socket sock(ioc);

    // Event providers.
    xavcore::SyscallEventProvider syscall_event_provider;

    // Event listeners.
    xavcore::RuleBasedDetectionListener rule_based_detection_listener(logger);
    auto ret =
        syscall_event_provider.listener_register(rule_based_detection_listener);
    if (!ret) {
        logger.error("Failed to register rule based detection listener: {}",
                     ret.error().message());
        return;
    }

    // Rules.
    auto anti_debug_rule =
        xavcore::rule_based_detection_listener_rules::AntiDebugRule();
    auto core_pattern_modification_rule = xavcore::
        rule_based_detection_listener_rules::CorePatternModificationRule();
    auto aslr_inspection_rule =
        xavcore::rule_based_detection_listener_rules::ASLRInspectionRule();
    auto cgroup_notify_on_release_rule = xavcore::
        rule_based_detection_listener_rules::CgroupNotifyOnReleaseRule();
    auto cgroup_release_agent_rule =
        xavcore::rule_based_detection_listener_rules::CgroupReleaseAgentRule();
    auto default_loader_modify_rule =
        xavcore::rule_based_detection_listener_rules::DefaultLoaderModifyRule();
    auto dynamic_code_loading_rule =
        xavcore::rule_based_detection_listener_rules::DynamicCodeLoadingRule();
    auto fileless_execution_rule =
        xavcore::rule_based_detection_listener_rules::FilelessExecutionRule();
    auto hidden_file_rule =
        xavcore::rule_based_detection_listener_rules::HiddenFileRule();
    auto kernel_module_loading_rule =
        xavcore::rule_based_detection_listener_rules::KernelModuleLoadingRule();
    auto process_vm_inject_rule =
        xavcore::rule_based_detection_listener_rules::ProcessVmInjectRule();
    auto proc_kcore_read_rule =
        xavcore::rule_based_detection_listener_rules::ProcKcoreReadRule();
    auto proc_mem_access_rule =
        xavcore::rule_based_detection_listener_rules::ProcMemAccessRule();
    std::vector<xavcore::IRuleBasedDetectionListenerRule*> rules{
        &anti_debug_rule,           &core_pattern_modification_rule,
        &aslr_inspection_rule,      &cgroup_notify_on_release_rule,
        &cgroup_release_agent_rule, &default_loader_modify_rule,
        &dynamic_code_loading_rule, &fileless_execution_rule,
        &hidden_file_rule,          &kernel_module_loading_rule,
        &process_vm_inject_rule,    &proc_kcore_read_rule,
        &proc_mem_access_rule};
    std::function<void(const xavcore::IRuleWarningInfo&)> cb =
        [&](const xavcore::IRuleWarningInfo& info) {
            if (const xavcore::rule_based_detection_listener_rules::
                    CorePatternModificationRuleWarningInfo* p =
                        dynamic_cast<decltype(p)>(&info)) {
                logger.warn(
                    "Core pattern modification rule is violated: severity = "
                    "{}, path = {}",
                    p->severity(), p->path);
            }
        };
    for (auto rule : rules) {
        (void)rule->register_warning_callback(cb);
        ret = rule_based_detection_listener.add_rule(*rule);
        if (!ret) {
            logger.error("Failed to add rule: {}", ret.error().message());
            return;
        }
    }

    // Start monitoring.
    if (!syscall_event_provider.start()) {
        logger.error("Failed to start syscall event provider");
        return;
    }

    // Accept connection asynchronously.
    acceptor.async_accept(sock, [&](boost::system::error_code ec) {
        if (ec) {
            logger.warn("Accept error: {}", ec.message());
        } else {
            logger.info("Client connected");
        }
    });

    logger.info("Xavcore Proactive Protection Module started");

    ioc.run();

    while (true);
}

void sigsegv_handler(int signum) {
    std::cerr << "SIGSEGV signal received" << std::endl;
    cpptrace::generate_trace().print();
    std::exit(signum);
}

int main(int argc, char* argv[]) {
    std::signal(SIGSEGV, sigsegv_handler);
    auto logger =
        spdlog::stdout_color_mt("Xavcore Proactive Protection Module");
    logger->set_level(spdlog::level::info);
    try {
        startup(*logger);
    } catch (std::exception& e) {
        logger->error("Fatal error: {}", e.what());
        cpptrace::generate_trace().print();
        exit(EXIT_FAILURE);
    }
    return 0;
}