#pragma once

#include "oatpp/Types.hpp"
#include "oatpp/macro/codegen.hpp"

#include OATPP_CODEGEN_BEGIN(DTO)

namespace xavagent {
ENUM(ScanStatusEnumDto, v_int32, VALUE(Scanning, 0, "Scanning"),
     VALUE(Paused, 1, "Paused"), VALUE(Stopped, 2, "Stopped"));

class MalwareInfoDto : public oatpp::DTO {
    DTO_INIT(MalwareInfoDto, DTO)

    DTO_FIELD(String, file_path);
    DTO_FIELD(String, malware_name);
};

class ScanStatusDto : public oatpp::DTO {
    DTO_INIT(ScanStatusDto, DTO)

    DTO_FIELD(Enum<ScanStatusEnumDto>::AsString, scan_status);
    DTO_FIELD(Int32, total_file_count);
    DTO_FIELD(Int32, scanned_file_count);
    DTO_FIELD(List<Object<MalwareInfoDto>>, malware_infos);
    DTO_FIELD(String, curr_scanning_file);
};

class OnAccessScannerStatusDto : public oatpp::DTO {
    DTO_INIT(OnAccessScannerStatusDto, DTO)

    DTO_FIELD(UInt64, scanned_object_count);
    DTO_FIELD(UInt64, blocked_object_count);
};
}  // namespace xavagent

#include OATPP_CODEGEN_END(DTO)
