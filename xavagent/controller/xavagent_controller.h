#pragma once

#include <format>
#include <oatpp/base/Log.hpp>
#include <oatpp/macro/codegen.hpp>
#include <oatpp/macro/component.hpp>
#include <oatpp/web/server/api/ApiController.hpp>
#include <thread>

#include "../dto/DTOs.h"
#include "../edr/scanner.h"
#include "xavlib/malware_info.pb.h"

#include OATPP_CODEGEN_BEGIN(ApiController)

namespace xavagent {
class XavAgentController : public oatpp::web::server::api::ApiController {
public:
    XavAgentController(OATPP_COMPONENT(
        std::shared_ptr<oatpp::web::mime::ContentMappers>, api_content_mappers))
        : oatpp::web::server::api::ApiController(api_content_mappers) {}

public:
    ENDPOINT("GET", "/", root) {
        auto dto = xavagent::ScanStatusDto::createShared();
        dto->total_file_count = 200;
        dto->curr_scanning_file = "Hello World!";
        return createDtoResponse(Status::CODE_200, dto);
    }

    ENDPOINT("GET", "/scan/quick/start", quick_scan) {
        if (this->scanner_.scan_status() != ScanStatus::Stopped) {
            OATPP_LOGi("Xav Agent", "Quick scan is already running");
            return this->createResponse(Status::CODE_403);
        }

        OATPP_LOGi("Xav Agent", "Execute quick scan");

        std::thread t([this]() {
            // std::vector<std::string> critical_paths{
            //     "/home", "/tmp",     "/var/tmp", "/bin",
            //     "/sbin", "/usr/bin", "/usr/sbin"};
            // FIXME: Only for test.
            std::vector<const char*> critical_paths{"/home/comma/projs/xav/"};
            for (const auto& path : critical_paths) {
                this->scanner_.scan(path, 4);
            }
            OATPP_LOGi("Xav Agent", "Quick scan completed");
        });
        t.detach();

        return this->createResponse(Status::CODE_200);
    }

    ENDPOINT("GET", "/scan/quick/status", quick_scan_status) {
        auto status = ScanStatusDto::createShared();
        status->scan_status = ScanStatusEnumDto(this->scanner_.scan_status());
        status->total_file_count = this->scanner_.total_file_count();
        status->scanned_file_count = this->scanner_.scanned_file_count();
        auto malware_infos = this->scanner_.malware_infos();
        for (const auto& info : malware_infos) {
            auto info_dto = MalwareInfoDto::createShared();
            info_dto->file_path = info.file_path.string();
            info_dto->malware_name = std::format(
                "{}.{}.{}",
                malware_info::MalwareType_Name(info.malware_info.type()),
                info.malware_info.family(), info.malware_info.variant());
            status->malware_infos->push_back(info_dto);
        }
        status->curr_scanning_file =
            this->scanner_.curr_scanning_file().string();
        return this->createDtoResponse(Status::CODE_200, status);
    }

private:
    Scanner scanner_;
};
}  // namespace xavagent

#include OATPP_CODEGEN_END(ApiController)
