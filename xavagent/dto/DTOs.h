#pragma once

#include "oatpp/Types.hpp"
#include "oatpp/macro/codegen.hpp"

#include OATPP_CODEGEN_BEGIN(DTO)

namespace xavagent {
class MalwareInfoDto : public oatpp::DTO {
    DTO_INIT(MalwareInfoDto, DTO)

    DTO_FIELD(String, file_path);
    DTO_FIELD(String, malware_name);
};

class ScanStatusDto : public oatpp::DTO {
    DTO_INIT(ScanStatusDto, DTO)

    DTO_FIELD(Int32, total_file_count);
    DTO_FIELD(Int32, scanned_file_count);
    DTO_FIELD(List<Object<MalwareInfoDto>>, malware_infos);
    DTO_FIELD(String, curr_scanning_file);
};
}  // namespace xavagent

#include OATPP_CODEGEN_END(DTO)
