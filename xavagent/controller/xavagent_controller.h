#pragma once

#include <oatpp/macro/codegen.hpp>
#include <oatpp/macro/component.hpp>
#include <oatpp/web/server/api/ApiController.hpp>

#include "../dto/DTOs.h"
#include "../edr/execution_monitor.h"
#include "../edr/scanner.h"

#include OATPP_CODEGEN_BEGIN(ApiController)

namespace xavagent {
class XavAgentController : public oatpp::web::server::api::ApiController {
public:
    XavAgentController(OATPP_COMPONENT(
        std::shared_ptr<oatpp::web::mime::ContentMappers>, api_content_mappers))
        : oatpp::web::server::api::ApiController(api_content_mappers) {}

public:
    ENDPOINT("GET", "/", root) {
        auto dto = xavagent::MyDto::createShared();
        dto->status_code = 200;
        dto->message = "Hello World!";
        return createDtoResponse(Status::CODE_200, dto);
    }

    ENDPOINT("GET", "/scan/quick", quick_scan) {
        OATPP_LOGi("Xav Agent", "Execute quick scan");
        std::vector<std::string> critical_paths{"/home",    "/tmp",  "/var/tmp",
                                                "/bin",     "/sbin", "/usr/bin",
                                                "/usr/sbin"};
        for (const auto& path : critical_paths) {
            this->scanner_.scan(path, 4);
        }
        return this->createResponse(Status::CODE_200);
    }

private:
    Scanner scanner_;
};
}  // namespace xavagent

#include OATPP_CODEGEN_END(ApiController)
