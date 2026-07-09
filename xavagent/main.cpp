#include <exception>

#include "app_component.h"
#include "controller/xavagent_controller.h"
#include "oatpp/network/Server.hpp"

void run() {
    // Register Components in scope of run() method
    xavagent::AppComponent components;

    // Get router component
    OATPP_COMPONENT(std::shared_ptr<oatpp::web::server::HttpRouter>, router);

    // Create XavAgentController and add all of its endpoints to router
    router->addController(std::make_shared<xavagent::XavAgentController>());

    // Get connection handler component
    OATPP_COMPONENT(std::shared_ptr<oatpp::network::ConnectionHandler>,
                    connection_handler);

    // Get connection provider component
    OATPP_COMPONENT(std::shared_ptr<oatpp::network::ServerConnectionProvider>,
                    connection_provider);

    // Create server which takes provided TCP connections and passes them to
    // HTTP connection handler
    oatpp::network::Server server(connection_provider, connection_handler);

    // Print info about server port
    OATPP_LOGi("Xav Agent", "Server running on port {}",
               connection_provider->getProperty("port").toString());

    // Run server
    server.run();
}

int run_main(int argc, const char* argv[]) {
    oatpp::Environment::init();

    run();

    oatpp::Environment::destroy();

    return 0;
}

int main(int argc, const char* argv[]) {
    try {
        return run_main(argc, argv);
    } catch (std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}
