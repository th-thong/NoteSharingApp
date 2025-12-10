#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H

#include <string>
#include <map>

class AuthManager {
private:
    // Map lưu session: Key = Token, Value = Username
    std::map<std::string, std::string> activeSessions;

public:
    AuthManager(); // Constructor

    // Đăng ký
    bool registerUser(std::string username, std::string password, std::string pubKey);

    // Đăng nhập, trả về Token
    std::string loginUser(std::string username, std::string password);

    // Kiểm tra token, trả về Username nếu hợp lệ
    std::string validateToken(std::string token);

    // Lấy Public Key của user (để client khác lấy về chia sẻ note)
    std::string getUserPublicKey(std::string username);
};

#endif