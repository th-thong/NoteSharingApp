cmake_minimum_required(VERSION 3.10)
project(SecureNoteApp LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ------------------------------------------------------------------------------
# 1. TÌM VÀ CẤU HÌNH THƯ VIỆN NGOÀI
# ------------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json 3.2.0 REQUIRED)
find_package(Threads REQUIRED)
find_package(GTest REQUIRED)

# ------------------------------------------------------------------------------
# 2. KHAI BÁO INCLUDE
# ------------------------------------------------------------------------------
include_directories(
    include
    include/client
    include/server
    include/common
    include/crypto
)

# ------------------------------------------------------------------------------
# 3. ĐỊNH NGHĨA CÁC CORE LIBRARIES
# ------------------------------------------------------------------------------

# 3.1 Crypto Library (Dùng chung cho Client & Server & Test)
add_library(crypto_lib src/crypto/CryptoManager.cpp)
target_link_libraries(crypto_lib OpenSSL::SSL OpenSSL::Crypto)

# 3.2 Server Logic Library (Auth, Note, Server Handler)
add_library(server_lib 
    src/server/Server.cpp 
    src/server/AuthManager.cpp 
    src/server/NoteManager.cpp
)
target_link_libraries(server_lib 
    crypto_lib 
    nlohmann_json::nlohmann_json 
    Threads::Threads 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# 3.3 Client Logic Library (ClientApp)
add_library(client_lib 
    src/client/ClientApp.cpp
)
target_link_libraries(client_lib 
    crypto_lib 
    nlohmann_json::nlohmann_json 
    Threads::Threads 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# ------------------------------------------------------------------------------
# 4. BUILD EXECUTABLES
# ------------------------------------------------------------------------------

# Server App
add_executable(server_app src/server/main_server.cpp)
target_link_libraries(server_app server_lib)

# Client App
add_executable(client_app src/client/main_client.cpp)
target_link_libraries(client_app client_lib)

# ------------------------------------------------------------------------------
# 5. BUILD TESTS
# ------------------------------------------------------------------------------
enable_testing()

# File thực thi test (Gồm các file test case)
add_executable(run_tests 
    project_02_test/crypto_test.cpp
    project_02_test/server_logic_test.cpp
)

# Link Test với các thư viện Logic và GTest
target_link_libraries(run_tests 
    crypto_lib
    server_lib
    GTest::GTest
    GTest::Main
    OpenSSL::SSL 
    OpenSSL::Crypto
    Threads::Threads
)

add_test(NAME AllTests COMMAND run_tests)

# ------------------------------------------------------------------------------
# 6. CẤU HÌNH CHO WINDOWS
# ------------------------------------------------------------------------------
if(WIN32)
    target_link_libraries(server_app ws2_32)
    target_link_libraries(client_app ws2_32)
endif()