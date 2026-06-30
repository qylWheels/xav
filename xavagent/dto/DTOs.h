#pragma once

#include "oatpp/Types.hpp"
#include "oatpp/macro/codegen.hpp"

#include OATPP_CODEGEN_BEGIN(DTO)

namespace xavagent {
class MyDto : public oatpp::DTO {
    DTO_INIT(MyDto, DTO)

    DTO_FIELD(Int32, status_code);
    DTO_FIELD(String, message);
};
}  // namespace xavagent

#include OATPP_CODEGEN_END(DTO)
