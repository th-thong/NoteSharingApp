#include "AuthManager.h"
#include "CryptoManager.h"
#include <fstream>
#include <filesystem>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
namespace fs = std::filesystem;


AuthManager::AuthManager() {
    if (!fs::exists("database/user")) {
        fs::create_directories("database/user");
    }
}

// Đăng ký người dùng
bool AuthManager::registerUser(std::string username, std::string password, std::string pubKey) {
    std::string userPath = "database/user/" + username + ".json";

    // Kiểm tra xem user đã tồn tại chưa
    if (fs::exists(userPath)) {
        std::cerr << "[AUTH] User " << username << " already exists." << std::endl;
        return false;
    }

    // Tạo Salt ngẫu nhiên
    std::string salt = CryptoManager::generateSalt();

    // Hash mật khẩu kèm Salt (Pass + Salt -> Hash)
    std::string hashedPassword = CryptoManager::hashPassword(password, salt);

    // Tạo JSON để lưu trữ thông tin
    json userJson;
    userJson["username"] = username;
    userJson["salt"] = salt;             // Lưu salt (để dùng khi login)
    userJson["hash"] = hashedPassword;   // Lưu hash (KHÔNG lưu password gốc)
    userJson["public_key"] = pubKey;     // Lưu public key Diffie-Hellman

    // D. Ghi xuống file
    try {
        std::ofstream file(userPath);
        file << userJson.dump(4);
        file.close();
        std::cout << "[AUTH] User " << username << " registered successfully." << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[AUTH] Error saving user: " << e.what() << std::endl;
        return false;
    }
}

// Đăng nhập người dùng
std::string AuthManager::loginUser(std::string username, std::string password) {
    std::string userPath = "database/user/" + username + ".json";

    // Kiểm tra user có tồn tại không
    if (!fs::exists(userPath)) {
        return "";
    }

    try {
        // Đọc file thông tin user
        std::ifstream file(userPath);
        json userJson;
        file >> userJson;

        std::string storedSalt = userJson["salt"];
        std::string storedHash = userJson["hash"];

        // Tính Hash của mật khẩu vừa nhập với Salt đã lưu
        std::string currentHash = CryptoManager::hashPassword(password, storedSalt);

        // So sánh Hash
        if (currentHash == storedHash) {
            // Đăng nhập thành công -> Tạo Token
            // (Trong thực tế nên dùng JWT, ở đây dùng Random String làm Token session)
            std::string token = CryptoManager::generateRandomKey(); 
            
            // Lưu token vào RAM (Session map)
            activeSessions[token] = username;
            
            std::cout << "[AUTH] User " << username << " logged in. Token: " << token << std::endl;
            return token;
        }
    } catch (const std::exception& e) {
        std::cerr << "[AUTH] Login error: " << e.what() << std::endl;
    }

    return "";
}

// 3. Kiểm tra Token (Xác thực session)
std::string AuthManager::validateToken(std::string token) {
    // Tìm token trong map session đang hoạt động
    auto it = activeSessions.find(token);
    
    if (it != activeSessions.end()) {
        return it->second; // Trả về username của token đó
    }
    
    return ""; // Token không hợp lệ hoặc đã hết hạn
}

// Lấy Public Key của một user (Dùng cho chức năng chia sẻ)
std::string AuthManager::getUserPublicKey(std::string username) {
    std::string userPath = "database/user/" + username + ".json";
    if (!fs::exists(userPath)) return "";
    
    try {
        std::ifstream file(userPath);
        json j;
        file >> j;
        return j["public_key"];
    } catch (...) {
        return "";
    }
}