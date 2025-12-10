#ifndef CLIENTAPP_H
#define CLIENTAPP_H

#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <nlohmann/json.hpp>

struct TLSConnection {
    SSL* ssl;
    int sockfd;
    SSL_CTX* ctx;
};

using json = nlohmann::json;

class ClientApp {

private:
    std::map<std::string, std::string> localKeys;
    std::string currentUsername;
    void loadLocalKeys();
    void saveLocalKeys();

public:
    // Token xác thực session
    std::string authToken;
    std::string refreshToken;
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
    std::map<std::string, std::string> noteKeys;

	// Constructor và Destructor
    ClientApp();
    ~ClientApp();


	// Đăng kí, Đăng nhập, Tải lên, Tải xuống, Xoá ghi chú
    void Login(TLSConnection conn);
    void Register(TLSConnection conn);
    void UploadNote(TLSConnection conn);
    void ListNotes(TLSConnection conn);
    void DownloadNote(TLSConnection conn);
    void DeleteNote(TLSConnection conn);
    std::string getKeyStorePath();


    void handleEvents();

    // Thiết lập kết nối TLS tới Server
    TLSConnection connectServer(const std::string& ip, int port);

    // Hiển thị menu lựa chọn
    void menu();

    // Đọc nội dung file từ ổ cứng
    std::string getNote(const char* filename);

	// Gửi và nhận gói tin JSON qua kết nối TLS
    bool sendPacket(TLSConnection& conn, int cmd, const json& payloadJson);
    json receivePacket(TLSConnection& conn);


    void savePrivateKey(const std::string& username, const std::vector<uint8_t>& privKey);
    bool loadPrivateKey(const std::string& username);

	// Chia sẻ ghi chú
    void ShareExistingNote(TLSConnection conn);
    void DownloadFromURL(TLSConnection conn);
    void ShareNote(TLSConnection conn);

	// Thiết lập workspace cho user
    void setupUserWorkspace(const std::string& username);
    void ListLocalFiles(const std::string& path);


};

#endif // CLIENTAPP_H