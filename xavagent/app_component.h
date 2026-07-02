#pragma once

#include "oatpp/json/ObjectMapper.hpp"
#include "oatpp/macro/component.hpp"
#include "oatpp/network/tcp/server/ConnectionProvider.hpp"
#include "oatpp/web/mime/ContentMappers.hpp"
#include "oatpp/web/server/HttpConnectionHandler.hpp"

namespace xavagent {
class AppComponent {
public:
    // Create ConnectionProvider component which listens on the port
    OATPP_CREATE_COMPONENT(
        std::shared_ptr<oatpp::network::ServerConnectionProvider>,
        server_connection_provider)([] {
        return oatpp::network::tcp::server::ConnectionProvider::createShared(
            {"0.0.0.0", 8000, oatpp::network::Address::IP_4});
    }());

    // Create Router component
    OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::web::server::HttpRouter>,
                           http_router)([] {
        return oatpp::web::server::HttpRouter::createShared();
    }());

    // Create ConnectionHandler component which uses Router component to route
    // requests
    OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::network::ConnectionHandler>,
                           server_connection_handler)([] {
        OATPP_COMPONENT(std::shared_ptr<oatpp::web::server::HttpRouter>,
                        router);  // get Router component
        return oatpp::web::server::HttpConnectionHandler::createShared(router);
    }());

    // Create ObjectMapper component to serialize/deserialize DTOs in
    // Contoller's API
    OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::web::mime::ContentMappers>,
                           api_content_mappers)([] {
        auto json = std::make_shared<oatpp::json::ObjectMapper>();
        json->serializerConfig().json.useBeautifier = true;

        auto mappers = std::make_shared<oatpp::web::mime::ContentMappers>();
        mappers->putMapper(json);

        return mappers;
    }());
};
}  // namespace xavagent
