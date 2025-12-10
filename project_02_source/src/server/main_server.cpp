#include "Server.h"
#include <iostream>
#include <exception>

int main() {
    try {
        int port = 8080;
        Server server(port);
        server.start();
    } catch (const std::exception& e) {
        std::cerr << "[FATAL ERROR] Server crashed: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "[FATAL ERROR] Unknown error occurred." << std::endl;
        return 1;
    }

    return 0;
}