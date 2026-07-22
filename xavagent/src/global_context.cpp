#include "global_context.h"

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <boost/asio.hpp>

namespace xavagent {
GlobalContext::GlobalContext(net::io_context& ioc)
    : ws_(net::make_strand(ioc)) {}
}  // namespace xavagent
