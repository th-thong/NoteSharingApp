#include "AuthManager.h"
#include "CryptoManager.h"
#include <fstream>
#include <filesystem>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
namespace fs = std::filesystem;

AuthManager::AuthManager(std::string rootPath) {
    if (rootPath.back() != '/' && rootPath.back() != '\\') {
        rootPath += "/";
    }

    // Thiết lập đường dẫn con
    this->USER_DIR = rootPath + "user/";

    // Tạo thư mục nếu chưa có
    if (!fs::exists(USER_DIR)) {
        fs::create_directories(USER_DIR);
    }
}

// Đăng ký người dùng
bool AuthManager::registerUser(std::string username, std::string password, std::string pubKey) {
    std::string userPath = USER_DIR + username + ".json";

    // Kiểm tra user tồn tại
    if (fs::exists(userPath)) {
        std::cerr << "[AUTH] User " << username << " already exists." << std::endl;
        return false;
    }

    try {
        // A. Tạo Salt và Hash password bằng PBKDF2
        std::vector<uint8_t> salt, hash;
        CryptoManager::hashPasswordPBKDF2(password, salt, hash);

        // B. Chuyển sang Base64 để lưu vào JSON
        std::string saltB64 = CryptoManager::base64Encode(salt);
        std::string hashB64 = CryptoManager::base64Encode(hash);

        // C. Lưu file
        json userJson;
        userJson["username"] = username;
        userJson["salt"] = saltB64;
        userJson["hash"] = hashB64;
        userJson["public_key"] = pubKey; // Client gửi lên đã là Base64

        std::ofstream file(userPath);
        file << userJson.dump(4);
        file.close();

        std::cout << "[AUTH] User " << username << " registered." << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[AUTH] Register error: " << e.what() << std::endl;
        return false;
    }
}

// Đăng nhập
std::string AuthManager::loginUser(std::string username, std::string password) {
    std::string userPath = USER_DIR + username + ".json";
    if (!fs::exists(userPath)) return "";

    try {
        // A. Đọc dữ liệu từ file
        std::ifstream file(userPath);
        json userJson;
        file >> userJson;

        // B. Decode Base64 lấy lại Salt và Hash gốc (dạng vector)
        std::string storedSaltB64 = userJson["salt"];
        std::string storedHashB64 = userJson["hash"];

        std::vector<uint8_t> storedSalt = CryptoManager::base64Decode(storedSaltB64);
        std::vector<uint8_t> storedHash = CryptoManager::base64Decode(storedHashB64);

        // C. Xác thực mật khẩu bằng PBKDF2
        if (CryptoManager::verifyPasswordPBKDF2(password, storedSalt, storedHash)) {
            // Đăng nhập thành công -> Tạo Token
            // Dùng generateRandomBytes(32) rồi encode base64 làm Token
            std::vector<uint8_t> tokenBytes = CryptoManager::generateRandomBytes(32);
            std::string token = CryptoManager::base64Encode(tokenBytes);

            activeSessions[token] = username;
            std::cout << "[AUTH] Login success: " << username << std::endl;
            return token;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[AUTH] Login error: " << e.what() << std::endl;
    }

    return "";
}

// Validate Token
std::string AuthManager::validateToken(std::string token) {
    auto it = activeSessions.find(token);
    if (it != activeSessions.end()) return it->second;
    return "";
}

// Get Public Key
std::string AuthManager::getUserPublicKey(std::string username) {
    std::string userPath = USER_DIR + username + ".json";
    if (!fs::exists(userPath)) return "";
    try {
        std::ifstream file(userPath);
        json j; file >> j;
        return j["public_key"];
    }
    catch (...) { return ""; }
}