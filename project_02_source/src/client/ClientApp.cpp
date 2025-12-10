#include "ClientApp.h"
#include "Protocol.h"
#include "CryptoManager.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <netdb.h>
#include <filesystem>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using json = nlohmann::json;
namespace fs = std::filesystem;

ClientApp::ClientApp() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

ClientApp::~ClientApp() {
    EVP_cleanup();
}

// ---------------------------------------------------------
//              Gửi/Nhận theo Protocol
// ---------------------------------------------------------

bool ClientApp::sendPacket(TLSConnection& conn, int cmd, const json& payloadJson) {
    std::string payloadStr = payloadJson.dump();

    PacketHeader header;
    header.cmd = (CommandType)cmd;
    header.payloadSize = (uint32_t)payloadStr.size();

    std::memset(header.token, 0, sizeof(header.token));
    if (!authToken.empty()) {
        std::strncpy(header.token, authToken.c_str(), sizeof(header.token) - 1);
    }

    if (SSL_write(conn.ssl, &header, sizeof(PacketHeader)) <= 0) {
        std::cerr << "[ERROR] Failed to send header." << std::endl;
        return false;
    }

    if (header.payloadSize > 0) {
        if (SSL_write(conn.ssl, payloadStr.c_str(), header.payloadSize) <= 0) {
            std::cerr << "[ERROR] Failed to send payload." << std::endl;
            return false;
        }
    }
    return true;
}

json ClientApp::receivePacket(TLSConnection& conn) {
    PacketHeader header;

    int bytesRead = SSL_read(conn.ssl, &header, sizeof(PacketHeader));
    if (bytesRead <= 0) {
        throw std::runtime_error("Connection closed by server or SSL error.");
    }

    if (header.payloadSize > 0) {
        std::vector<char> buffer(header.payloadSize + 1);
        int totalReceived = 0;

        while (totalReceived < (int)header.payloadSize) {
            int r = SSL_read(conn.ssl, buffer.data() + totalReceived, header.payloadSize - totalReceived);
            if (r <= 0) throw std::runtime_error("Incomplete payload received.");
            totalReceived += r;
        }
        buffer[header.payloadSize] = '\0';

        return json::parse(buffer.data());
    }

    return json({});
}

// ---------------------------------------------------------
//             Kết nối tới Server
// ---------------------------------------------------------

TLSConnection ClientApp::connectServer(const std::string& ip, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return { NULL, -1, NULL };
    }

    struct sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    struct hostent* host = gethostbyname(ip.c_str());
    if (host == NULL) {
        if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
            std::cerr << "[ERROR] Invalid address/ Host not found: " << ip << std::endl;
            close(sockfd);
            return { NULL, -1, NULL };
        }
    }
    else {
        std::memcpy((char*)&server_addr.sin_addr.s_addr, (char*)host->h_addr, host->h_length);
    }

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return { NULL, -1, NULL };
    }

    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "[ERROR] Unable to create SSL context" << std::endl;
        close(sockfd);
        return { NULL, -1, NULL };
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return { NULL, -1, NULL };
    }

    std::cout << "[INFO] Connected to Server over SSL/TLS!" << std::endl;
    return TLSConnection{ ssl, sockfd, ctx };
}

// ---------------------------------------------------------
//              Menu và Xử lý sự kiện
// ---------------------------------------------------------

void ClientApp::menu() {
    std::cout << "\n=== SECURE NOTE APP ===" << std::endl;
    std::cout << "1. Login" << std::endl;
    std::cout << "2. Register" << std::endl;
    std::cout << "3. Upload Note" << std::endl;
    std::cout << "4. List My Notes" << std::endl;
    std::cout << "5. Share Note (Generate URL)" << std::endl;
    std::cout << "6. Download from URL" << std::endl;
    std::cout << "7. Download My Note" << std::endl;
    std::cout << "8. Delete My Note" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << "Select: ";
}

void ClientApp::handleEvents() {
    std::string server_ip;
    int port;
    
    server_ip = "server";
    port = 8080;
    std::cout << "Connecting to " << server_ip << ":" << port << "...\n";

    TLSConnection conn = connectServer(server_ip, port);
    if (conn.ssl == NULL) return;

    int choice = -1;
    while (choice != 0) {
        menu();
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(1000, '\n');
            continue;
        }

        try {
            switch (choice) {
            case 1: Login(conn); 
                break;
            case 2: Register(conn); 
                break;
            case 3: UploadNote(conn); 
                break;
            case 4: ListNotes(conn); 
                break;
            case 5: ShareNote(conn); 
                break; 
            case 6: DownloadFromURL(conn); 
                break;
            case 7: DownloadNote(conn); 
                break;
            case 8: DeleteNote(conn); 
                break;
            case 0: std::cout << "Exiting..." << std::endl; 
                break;
            default: std::cout << "Invalid choice." << std::endl;
                break;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[ERROR] Exception: " << e.what() << std::endl;
            break;
        }
    }

    SSL_shutdown(conn.ssl);
    SSL_free(conn.ssl);
    SSL_CTX_free(conn.ctx);
    close(conn.sockfd);
}

// ---------------------------------------------------------
//              ĐĂNG NHẬP / ĐĂNG KÝ
// ---------------------------------------------------------
void ClientApp::Login(TLSConnection conn) {
    std::string username, password;
    std::cout << "Username: "; std::cin >> username;
    std::cout << "Password: "; std::cin >> password;

    json req;
    req["username"] = username;
    req["password"] = password;

    if (!sendPacket(conn, (int)CommandType::LOGIN, req)) return;

    json res = receivePacket(conn);

    if (res.contains("token") && !res["token"].is_null()) {
        authToken = res["token"];
        currentUsername = username;
        std::cout << "[SUCCESS] Logged in! Token saved." << std::endl;
        setupUserWorkspace(username);
        loadLocalKeys();
        if (loadPrivateKey(username)) {
            std::cout << "[INFO] Private key loaded for E2EE." << std::endl;
        }
        else {
            std::cout << "[WARN] Private key not found on this device. E2EE features will fail." << std::endl;
        }
    }
    else {
        std::cerr << "[FAILED] Login failed: " << res.value("message", "Unknown error") << std::endl;
    }
}

void ClientApp::Register(TLSConnection conn) {
    std::string username, password;
    std::cout << "New Username: "; std::cin >> username;
    std::cout << "New Password: "; std::cin >> password;

    CryptoManager::generateDHKeyPair(public_key, private_key);
    std::string pubKeyStr = CryptoManager::base64Encode(public_key);

    json req;
    req["username"] = username;
    req["password"] = password;
    req["public_key"] = pubKeyStr;

    if (!sendPacket(conn, (int)CommandType::REGISTER, req)) return;

    json res = receivePacket(conn);

    if (res.value("status", "") == "ok") {
        std::cout << "[SUCCESS] Registered successfully!" << std::endl;
        setupUserWorkspace(username);
        savePrivateKey(username, private_key);
    }
    else {
        std::cerr << "[FAILED] Register error: " << res.value("message", "Unknown") << std::endl;
    }
}

// ---------------------------------------------------------
//              CHỨC NĂNG: UPLOAD NOTE
// ---------------------------------------------------------

void ClientApp::UploadNote(TLSConnection conn) {
    if (authToken.empty()) {
        std::cerr << "[ERROR] Login required." << std::endl;
        return;
    }
    
    std::string workspacePath="client_data/" + currentUsername + "/data/";
    std::cout<<"Your workspace is at "+ workspacePath + "\n";
    ListLocalFiles(workspacePath);

    std::string filename;
    std::cout << "Enter filename path to upload (e.g. " + workspacePath + "a.txt): ";
    std::cin >> filename;

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Cannot open file: " << filename << std::endl;
        return;
    }

    std::vector<uint8_t> fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (fileContent.empty()) {
        std::cerr << "[ERROR] File is empty." << std::endl;
        return;
    }

    try {
        std::vector<uint8_t> noteKey = CryptoManager::generateRandomBytes(32);
        std::vector<uint8_t> iv;
        std::vector<uint8_t> tag;
        std::vector<uint8_t> cipherBytes;

        if (!CryptoManager::aesEncrypt(fileContent, noteKey, iv, tag, cipherBytes)) {
            std::cerr << "[ERROR] Encryption failed." << std::endl;
            return;
        }
        std::filesystem::path p(filename);
        std::string baseName = p.filename().string();

        json req;
        req["token"] = authToken;
        req["cipher_text"] = CryptoManager::base64Encode(cipherBytes);
        req["iv"] = CryptoManager::base64Encode(iv);
        req["tag"] = CryptoManager::base64Encode(tag);
        req["filename"] = baseName;

        if (!sendPacket(conn, (int)CommandType::UPLOAD_NOTE, req)) return;

        json res = receivePacket(conn);

        if (res.value("status", "") == "ok") {
            std::string noteId = res["noteId"];
            localKeys[noteId] = CryptoManager::base64Encode(noteKey);
            saveLocalKeys();

            std::cout << "[SUCCESS] Note uploaded with ID: " << noteId << std::endl;
        }
        else {
            std::cerr << "[FAILED] Upload error: " << res.value("message", "Unknown") << std::endl;
        }

    }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] Processing error: " << e.what() << std::endl;
    }
}

// ---------------------------------------------------------
//              QUẢN LÝ KHÓA CỤC BỘ
// ---------------------------------------------------------
void ClientApp::savePrivateKey(const std::string& username, const std::vector<uint8_t>& privKey) {
    std::ofstream f("client_data/" + username + "/data/" + username + ".priv", std::ios::binary);
    f.write(reinterpret_cast<const char*>(privKey.data()), privKey.size());
    f.close();
}

bool ClientApp::loadPrivateKey(const std::string& username) {
    std::ifstream f("client_data/" + username + "/data/" + username + ".priv", std::ios::binary);
    if (!f.is_open()) return false;

    private_key.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}


std::string ClientApp::getKeyStorePath() {
    if (currentUsername.empty()) return "";
    return "client_data/" + currentUsername + "/data/client_keys.json";
}


void ClientApp::loadLocalKeys() {
    if (std::filesystem::exists(getKeyStorePath())) {
        try {
            std::ifstream f(getKeyStorePath());
            json j; f >> j;
            localKeys = j.get<std::map<std::string, std::string>>();
        }
        catch (...) {}
    }
}

void ClientApp::saveLocalKeys() {
    std::ofstream f(getKeyStorePath());
    json j(localKeys);
    f << j.dump(4);
    f.close();
}

// ---------------------------------------------------------
//              CHỨC NĂNG: LIỆT KÊ GHI CHÚ
// ---------------------------------------------------------
void ClientApp::ListNotes(TLSConnection conn) {
    if (authToken.empty()) {
        std::cerr << "[ERROR] Login required." << std::endl;
        return;
    }

    json req;
    req["token"] = authToken;

    if (!sendPacket(conn, (int)CommandType::GET_METADATA, req)) return;
    json res = receivePacket(conn);

    if (res.is_array()) {
        std::cout << "\n=== MY WORKSPACE ===" << std::endl;
        // Thêm cột Filename vào giao diện
        std::printf("%-15s | %-30s | %-25s\n", "Note ID", "Filename", "Upload Time");
        std::cout << "-----------------------------------------------------------------------------" << std::endl;
        
        for (auto& item : res) {
            std::string id = item.value("noteId", "N/A");
            // Lấy tên file gốc (Server đã được sửa ở bước trước để gửi field này)
            std::string fname = item.value("filename", "Unknown");
            
            time_t upTime = item.value("uploadTime", 0);
            std::string timeStr = "Unknown";
            if (upTime > 0) {
                char buffer[26];
                ctime_r(&upTime, buffer);
                timeStr = buffer;
                if (!timeStr.empty() && timeStr.back() == '\n') timeStr.pop_back();
            }
            // In ra 3 cột
            std::printf("%-15s | %-30s | %-25s\n", id.c_str(), fname.c_str(), timeStr.c_str());
        }
        std::cout << "-----------------------------------------------------------------------------" << std::endl;
    }
    else {
        std::cout << "[ERROR] Failed to list notes or workspace is empty." << std::endl;
    }
}


// ---------------------------------------------------------
//              CHỨC NĂNG: DOWNLOAD NOTE (OWNER)
// ---------------------------------------------------------
void ClientApp::DownloadNote(TLSConnection conn) {
    if (authToken.empty()) { std::cerr << "[ERROR] Login required." << std::endl; return; }

    std::string noteId;
    std::cout << "Enter Note ID: "; std::cin >> noteId;

    std::string keyB64 = localKeys.count(noteId) ? localKeys[noteId] : "";
    if (keyB64.empty()) {
        std::cout << "[WARN] Key not found locally. Enter Key (Base64): "; std::cin >> keyB64;
    }

    json req;
    req["token"] = authToken;
    req["noteId"] = noteId;

    if (!sendPacket(conn, (int)CommandType::DOWNLOAD_NOTE, req)) return;
    json res = receivePacket(conn);

    if (res.contains("cipher_text")) {
        try {
            std::vector<uint8_t> cipher = CryptoManager::base64Decode(res["cipher_text"]);
            std::vector<uint8_t> iv = CryptoManager::base64Decode(res["iv"]);
            std::vector<uint8_t> tag = CryptoManager::base64Decode(res["tag"]);
            std::vector<uint8_t> key = CryptoManager::base64Decode(keyB64);
            std::vector<uint8_t> plain;

            if (CryptoManager::aesDecrypt(cipher, key, iv, tag, plain)) {
                std::string originalName = res.value("filename", "unknown_share.bin");

                std::string saveDir = "downloads/";
                if (!currentUsername.empty()) {
                    saveDir = "client_data/" + currentUsername + "/downloads/";
                }

                if (!fs::exists(saveDir)) {
                    fs::create_directories(saveDir);
                }

                std::string outPath = saveDir + originalName;

                std::ofstream f(outPath, std::ios::binary);
                f.write((char*)plain.data(), plain.size());
                f.close();
                std::cout << "[SUCCESS] File saved as: " << outPath << std::endl;
            }
            else {
                std::cerr << "[ERROR] Decryption failed! Key incorrect?" << std::endl;
            }
        }
        catch (...) { std::cout << "[ERROR] Exception during decryption." << std::endl; }
    }
    else {
        std::cout << "[ERROR] " << res.value("message", "Failed to download") << std::endl;
    }
}



// ---------------------------------------------------------
//              Share Note
// ---------------------------------------------------------
void ClientApp::ShareNote(TLSConnection conn) {
    if (authToken.empty()) { std::cout << "[ERROR] Login required." << std::endl; return; }
    if (private_key.empty()) { std::cout << "[ERROR] Private key missing. Cannot perform E2EE." << std::endl; return; }

    ListNotes(conn);
    std::string noteId, recipient;

    std::cout << "\n=== SHARE NOTE (End-to-End Encrypted) ===" << std::endl;
    std::cout << "Enter Note ID to share: "; std::cin >> noteId;
    std::cout << "Enter Recipient Username: "; std::cin >> recipient;

    int hours, views;
    std::cout << "Link expiration (hours): ";
    if (!(std::cin >> hours)) { 
        std::cin.clear(); std::cin.ignore(1000, '\n'); hours = 24; 
    }

    std::cout << "Max views (e.g. 1): ";
    if (!(std::cin >> views)) {
        std::cin.clear(); std::cin.ignore(1000, '\n'); views = 1; 
    }


    if (localKeys.find(noteId) == localKeys.end()) {
        std::cout << "[ERROR] Encryption Key for this note not found locally." << std::endl; return;
    }
    std::vector<uint8_t> noteKey = CryptoManager::base64Decode(localKeys[noteId]);

    json reqKey; reqKey["username"] = recipient;
    if (!sendPacket(conn, (int)CommandType::GET_PUBLIC_KEY, reqKey)) return;
    json resKey = receivePacket(conn);

    if (resKey.value("status", "") != "ok") {
        std::cout << "[ERROR] Recipient not found or has no public key." << std::endl; return;
    }
    std::vector<uint8_t> recipientPubKey = CryptoManager::base64Decode(resKey["public_key"]);

    std::cout << "[INFO] Encrypting key for " << recipient << "..." << std::endl;
    std::vector<uint8_t> sharedSecret = CryptoManager::deriveSharedSecret(private_key, recipientPubKey);

    std::vector<uint8_t> encKey, iv, tag;
    CryptoManager::aesEncrypt(noteKey, sharedSecret, iv, tag, encKey);

    json reqShare;
    reqShare["token"] = authToken;
    reqShare["noteId"] = noteId;
    reqShare["recipient"] = recipient;
    reqShare["encrypted_key"] = CryptoManager::base64Encode(encKey);
    reqShare["iv"] = CryptoManager::base64Encode(iv);
    reqShare["tag"] = CryptoManager::base64Encode(tag);

    reqShare["duration"] = hours * 3600; 
    reqShare["max_views"] = views;

    if (!sendPacket(conn, (int)CommandType::SHARE_NOTE, reqShare)) return;
    json resShare = receivePacket(conn);

    if (resShare.value("status", "") == "ok") {
        std::string shareId = resShare["shareId"];
        std::cout << "\n[SUCCESS] Encrypted Link Created!" << std::endl;
        std::cout << "---------------------------------------------------" << std::endl;
        std::cout << "URL: securenote://" << shareId << std::endl;
        std::cout << "---------------------------------------------------" << std::endl;
        std::cout << "Settings: Expire in " << hours << "h, Max views: " << views << std::endl;
        std::cout << "Send this URL to user '" << recipient << "'." << std::endl;
    }
    else {
        std::cerr << "[FAILED] " << resShare.value("message", "Unknown error") << std::endl;
    }
}

// ---------------------------------------------------------
//              Download file từ URL
// ---------------------------------------------------------
void ClientApp::DownloadFromURL(TLSConnection conn) {
    if (authToken.empty()) { std::cout << "[ERROR] Login required to verify identity." << std::endl; return; }
    if (private_key.empty()) { std::cout << "[ERROR] Private key missing." << std::endl; return; }

    std::string url;
    std::cout << "Paste the URL (securenote://...): "; std::cin >> url;

    std::string prefix = "securenote://";
    size_t prefixPos = url.find(prefix);
    if (prefixPos == std::string::npos) {
        std::cerr << "[ERROR] Invalid URL format!" << std::endl; return;
    }
    std::string shareId = url.substr(prefix.length());

    json req; req["shareId"] = shareId;
    if (!sendPacket(conn, (int)CommandType::DOWNLOAD_SHARED, req)) return;
    json res = receivePacket(conn);

    if (!res.contains("encrypted_key")) {
        std::cout << "[ERROR] Link invalid, expired or access denied." << std::endl; return;
    }

    try {
        std::string sender = res["sender"];
        std::cout << "[INFO] Note sent by: " << sender << std::endl;

        json reqKey; reqKey["username"] = sender;
        if (!sendPacket(conn, (int)CommandType::GET_PUBLIC_KEY, reqKey)) return;
        json resKey = receivePacket(conn);
        std::vector<uint8_t> senderPubKey = CryptoManager::base64Decode(resKey["public_key"]);

        std::vector<uint8_t> sharedSecret = CryptoManager::deriveSharedSecret(private_key, senderPubKey);
        std::vector<uint8_t> encKey = CryptoManager::base64Decode(res["encrypted_key"]);
        std::vector<uint8_t> kIv = CryptoManager::base64Decode(res["key_iv"]);
        std::vector<uint8_t> kTag = CryptoManager::base64Decode(res["key_tag"]);
        std::vector<uint8_t> noteKey;

        if (!CryptoManager::aesDecrypt(encKey, sharedSecret, kIv, kTag, noteKey)) {
            std::cout << "[ERROR] E2EE Decryption Failed! Wrong identity." << std::endl; return;
        }

        std::vector<uint8_t> cipher = CryptoManager::base64Decode(res["cipher_text"]);
        std::vector<uint8_t> cIv = CryptoManager::base64Decode(res["iv"]);
        std::vector<uint8_t> cTag = CryptoManager::base64Decode(res["tag"]);
        std::vector<uint8_t> plain;

        if (CryptoManager::aesDecrypt(cipher, noteKey, cIv, cTag, plain)) {
            std::string originalName = res.value("filename", "unknown_share.bin");

            std::string saveDir = "downloads/";
            if (!currentUsername.empty()) {
                saveDir = "client_data/" + currentUsername + "/downloads/";
            }

            if (!fs::exists(saveDir)) {
                fs::create_directories(saveDir);
            }

            std::string outPath = saveDir + originalName;

            std::ofstream f(outPath, std::ios::binary);
            f.write((char*)plain.data(), plain.size());
            f.close();
            std::cout << "[SUCCESS] Decrypted & Saved to: " << outPath << std::endl;
        }
        else {
            std::cout << "[ERROR] Content Decryption Failed." << std::endl;
        }

    }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
    }
}


// ---------------------------------------------------------
//      Tạo workspace cho user
// ---------------------------------------------------------
void ClientApp::setupUserWorkspace(const std::string& username) {
    try {
        std::string userRoot = "client_data/" + username;
        std::string downloadPath = userRoot + "/downloads";
        std::string dataPath = userRoot + "/data";

        if (!fs::exists(userRoot)) fs::create_directories(userRoot);
        if (!fs::exists(downloadPath)) fs::create_directories(downloadPath);
        if (!fs::exists(dataPath)) fs::create_directories(dataPath);

        std::cout << "[INFO] User workspace created at: " << userRoot << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed to create user directories: " << e.what() << std::endl;
    }
}



void ClientApp::DeleteNote(TLSConnection conn) {
    if (authToken.empty()) { 
        std::cerr << "[ERROR] Login required." << std::endl; 
        return; 
    }

    // Hiện danh sách để chọn file xóa
    ListNotes(conn);

    std::string noteId;
    std::cout << "\n=== DELETE NOTE ===" << std::endl;
    std::cout << "Enter Note ID to delete: "; 
    std::cin >> noteId;

    // Xác nhận
    std::string confirm;
    std::cout << "Are you sure you want to delete " << noteId << "? (y/n): ";
    std::cin >> confirm;
    if (confirm != "y" && confirm != "Y") {
        std::cout << "[INFO] Cancelled." << std::endl;
        return;
    }

    json req;
    req["token"] = authToken;
    req["noteId"] = noteId;

    if (!sendPacket(conn, (int)CommandType::DELETE_NOTE, req)) return;
    json res = receivePacket(conn);

    if (res.value("status", "") == "ok") {
        std::cout << "[SUCCESS] Note deleted from server." << std::endl;
        
        // Xóa Key trong Local Store để dọn dẹp
        if (localKeys.count(noteId)) {
            localKeys.erase(noteId);
            saveLocalKeys();
            std::cout << "[INFO] Removed encryption key from local storage." << std::endl;
        }
    } else {
        std::cerr << "[FAILED] Delete error: " << res.value("message", "Unknown or Permission denied") << std::endl;
    }
}



void ClientApp::ListLocalFiles(const std::string& path) {
    if (!fs::exists(path)) {
        std::cout << "[INFO] Directory does not exist: " << path << std::endl;
        return;
    }

    std::cout << "\n--- FILES IN: " << path << " ---" << std::endl;
    bool isEmpty = true;

    try {
        for (const auto& entry : fs::directory_iterator(path)) {
            if (entry.is_regular_file()) { // Chỉ hiện file, bỏ qua thư mục con
                isEmpty = false;
                std::string filename = entry.path().filename().string();
                uintmax_t size = entry.file_size();
                std::cout << "- " << filename << " (" << size << " bytes)" << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Listing failed: " << e.what() << std::endl;
    }

    if (isEmpty) {
        std::cout << "(Empty directory)" << std::endl;
    }
    std::cout << "-----------------------------------" << std::endl;
}