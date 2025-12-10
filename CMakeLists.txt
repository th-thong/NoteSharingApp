cmake_minimum_required(VERSION 3.10)

project(SecureNoteApp LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ------------------------------------------------------------------------------
# 1. TÌM VÀ CẤU HÌNH THƯ VIỆN
# ------------------------------------------------------------------------------

# Tìm OpenSSL (Mã hóa)
find_package(OpenSSL REQUIRED)

# Tìm nlohmann_json (Xử lý JSON/JWT)
find_package(nlohmann_json 3.2.0 REQUIRED)

# Tìm Threads (Cần thiết cho Networking trên Linux)
find_package(Threads REQUIRED)

# Tìm GTest
find_package(GTest REQUIRED) 

# ------------------------------------------------------------------------------
# 2. KHAI BÁO ĐƯỜNG DẪN HEADER
# ------------------------------------------------------------------------------
# Giúp compiler tìm thấy các file .h trong thư mục include
include_directories(
    project_02_source/include
    project_02_source/include/client
    project_02_source/include/server
    project_02_source/include/common
    project_02_source/include/crypto
)

# ------------------------------------------------------------------------------
# 3. BUILD SERVER (MÁY CHỦ)
# ------------------------------------------------------------------------------
add_executable(server_app
    project_02_source/src/server/main_server.cpp
    project_02_source/src/server/Server.cpp
    project_02_source/src/server/AuthManager.cpp
    project_02_source/src/server/NoteManager.cpp
    project_02_source/src/crypto/CryptoManager.cpp
)

# Liên kết thư viện cho Server
target_link_libraries(server_app 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    nlohmann_json::nlohmann_json
    Threads::Threads
)

# ------------------------------------------------------------------------------
# 4. BUILD CLIENT (MÁY KHÁCH)
# ------------------------------------------------------------------------------
add_executable(client_app
    project_02_source/src/client/main_client.cpp
    project_02_source/src/client/ClientApp.cpp
    project_02_source/src/crypto/CryptoManager.cpp # Client cần Crypto để mã hóa file
)

# Liên kết thư viện cho Client
target_link_libraries(client_app 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    nlohmann_json::nlohmann_json
    Threads::Threads
)

# ------------------------------------------------------------------------------
# 5. CẤU HÌNH CHO WINDOWS (Nếu bạn chạy build trực tiếp trên Win thay vì Docker)
# ------------------------------------------------------------------------------
if(WIN32)
    # Link thêm thư viện socket của Windows (ws2_32)
    target_link_libraries(server_app ws2_32)
    target_link_libraries(client_app ws2_32)
endif()

# ------------------------------------------------------------------------------
# 6. BUILD TEST
# ------------------------------------------------------------------------------
# enable_testing()
# add_executable(run_tests project_02_test/TestCrypto.cpp project_02_source/src/crypto/CryptoManager.cpp)
# target_link_libraries(run_tests GTest::gtest GTest::gtest_main OpenSSL::SSL OpenSSL::Crypto)