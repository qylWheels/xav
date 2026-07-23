#pragma once

#include <format>
#include <oatpp/base/Log.hpp>
#include <oatpp/macro/codegen.hpp>
#include <oatpp/macro/component.hpp>
#include <oatpp/web/server/api/ApiController.hpp>
#include <thread>

#include "xavagent/api/DTOs.h"
#include "xavagent/global_context.h"
#include "xavagent/scan/scanner.h"

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
        auto& scanner = GlobalContext::get_global_context().scanner();
        if (scanner.scan_status() != ScanStatus::Stopped) {
            OATPP_LOGi("Xav Agent", "Quick scan is already running");
            return this->createResponse(Status::CODE_403);
        }

        OATPP_LOGi("Xav Agent", "Execute quick scan");

        std::thread t([this, &scanner]() {
            // std::vector<std::string> critical_paths{
            //     "/home", "/tmp",     "/var/tmp", "/bin",
            //     "/sbin", "/usr/bin", "/usr/sbin"};
            // FIXME: Only for test.
            std::vector<const char*> critical_paths{"/home/qyl/projects/xav/"};
            for (const auto& path : critical_paths) {
                scanner.scan(path, 4);
            }
            OATPP_LOGi("Xav Agent", "Quick scan completed");
        });
        t.detach();

        return this->createResponse(Status::CODE_200);
    }

    ENDPOINT("GET", "/scan/quick/status", quick_scan_status) {
        auto status = ScanStatusDto::createShared();
        auto& scanner = GlobalContext::get_global_context().scanner();
        status->scan_status = ScanStatusEnumDto(scanner.scan_status());
        status->total_file_count = scanner.total_file_count();
        status->scanned_file_count = scanner.scanned_file_count();
        auto malware_infos = scanner.malware_infos();
        status->malware_infos = {};
        for (const auto& info : malware_infos) {
            auto info_dto = MalwareInfoDto::createShared();
            info_dto->file_path = info.file_path.string();
            info_dto->malware_name = std::format(
                "{}.{}.{}",
                malware_info::MalwareType_Name(info.malware_info.type()),
                info.malware_info.family(), info.malware_info.variant());
            status->malware_infos->push_back(info_dto);
        }
        status->curr_scanning_file = scanner.curr_scanning_file().string();
        return this->createDtoResponse(Status::CODE_200, status);
    }

    ENDPOINT("GET", "/on-access-scanner/status", on_access_scanner_status) {
        auto status = OnAccessScannerStatusDto::createShared();
        auto& on_access_scanner =
            GlobalContext::get_global_context().on_access_scanner();
        status->scanned_object_count = on_access_scanner.scanned_object_count();
        status->blocked_object_count = on_access_scanner.blocked_object_count();
        return this->createDtoResponse(Status::CODE_200, status);
    }

    ENDPOINT("GET", "/behavior-monitor/status", behavior_monitor_status) {
        auto status = BehaviorMonitorStatusDto::createShared();
        auto& behav_monitor =
            GlobalContext::get_global_context().behavior_monitor();
        status->total_event_count = behav_monitor.total_event_count();
        status->suspicious_event_count = behav_monitor.suspicious_event_count();
        return this->createDtoResponse(Status::CODE_200, status);
    }
};
}  // namespace xavagent

#include OATPP_CODEGEN_END(ApiController)
