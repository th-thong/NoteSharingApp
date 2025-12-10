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

// Include cho Socket trên Linux
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;
using json = nlohmann::json;
namespace fs = std::filesystem;

// Constructor
ClientApp::ClientApp() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    loadLocalKeys();
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

    memset(header.token, 0, sizeof(header.token));
    if (!authToken.empty()) {
        strncpy(header.token, authToken.c_str(), sizeof(header.token) - 1);
    }

    if (SSL_write(conn.ssl, &header, sizeof(PacketHeader)) <= 0) {
        cerr << "[ERROR] Failed to send header." << endl;
        return false;
    }

    if (header.payloadSize > 0) {
        if (SSL_write(conn.ssl, payloadStr.c_str(), header.payloadSize) <= 0) {
            cerr << "[ERROR] Failed to send payload." << endl;
            return false;
        }
    }
    return true;
}

json ClientApp::receivePacket(TLSConnection& conn) {
    PacketHeader header;

    int bytesRead = SSL_read(conn.ssl, &header, sizeof(PacketHeader));
    if (bytesRead <= 0) {
        throw runtime_error("Connection closed by server or SSL error.");
    }

    if (header.payloadSize > 0) {
        vector<char> buffer(header.payloadSize + 1);
        int totalReceived = 0;

        while (totalReceived < (int)header.payloadSize) {
            int r = SSL_read(conn.ssl, buffer.data() + totalReceived, header.payloadSize - totalReceived);
            if (r <= 0) throw runtime_error("Incomplete payload received.");
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
    memset(&server_addr, 0, sizeof(server_addr));
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
        memcpy((char*)&server_addr.sin_addr.s_addr, (char*)host->h_addr, host->h_length);
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
    cout << "\n=== SECURE NOTE APP (E2EE Only) ===" << endl;
    cout << "1. Login" << endl;
    cout << "2. Register" << endl;
    cout << "3. Upload Note" << endl;
    cout << "4. List My Notes" << endl;
    cout << "5. Share Note (Generate URL)" << endl;
    cout << "6. Download from URL" << endl;
    cout << "7. Download My Note" << endl;
    cout << "0. Exit" << endl;
    cout << "Select: ";
}

void ClientApp::handleEvents() {
    string server_ip;
    int port;
    
    // Kết nối đến server
    server_ip = "server";
    port = 8080;
    cout << "Connecting to " << server_ip << ":" << port << "...\n";

    TLSConnection conn = connectServer(server_ip, port);
    if (conn.ssl == NULL) return;

    int choice = -1;
    while (choice != 0) {
        menu();
        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(1000, '\n');
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
            case 0: cout << "Exiting..." << endl; 
                break;
            default: cout << "Invalid choice." << endl;
                break;
            }
        }
        catch (const std::exception& e) {
            cerr << "[ERROR] Exception: " << e.what() << endl;
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
    string username, password;
    cout << "Username: "; cin >> username;
    cout << "Password: "; cin >> password;

    json req;
    req["username"] = username;
    req["password"] = password;

    if (!sendPacket(conn, (int)CommandType::LOGIN, req)) return;

    json res = receivePacket(conn);

    if (res.contains("token") && !res["token"].is_null()) {
        authToken = res["token"];
        currentUsername = username;
        cout << "[SUCCESS] Logged in! Token saved." << endl;
        setupUserWorkspace(username);
        if (loadPrivateKey(username)) {
            cout << "[INFO] Private key loaded for E2EE." << endl;
        }
        else {
            cout << "[WARN] Private key not found on this device. E2EE features will fail." << endl;
        }
    }
    else {
        cerr << "[FAILED] Login failed: " << res.value("message", "Unknown error") << endl;
    }
}

void ClientApp::Register(TLSConnection conn) {
    string username, password;
    cout << "New Username: "; cin >> username;
    cout << "New Password: "; cin >> password;

    // Tạo cặp khóa DH cho người dùng mới
    CryptoManager::generateDHKeyPair(public_key, private_key);
    string pubKeyStr = CryptoManager::base64Encode(public_key);

    json req;
    req["username"] = username;
    req["password"] = password;
    req["public_key"] = pubKeyStr; // Gửi Public Key lên Server

    if (!sendPacket(conn, (int)CommandType::REGISTER, req)) return;

    json res = receivePacket(conn);

    if (res.value("status", "") == "ok") {
        cout << "[SUCCESS] Registered successfully!" << endl;
        setupUserWorkspace(username);
        savePrivateKey(username, private_key); // Lưu Private Key vào máy
    }
    else {
        cerr << "[FAILED] Register error: " << res.value("message", "Unknown") << endl;
    }
}

// ---------------------------------------------------------
//              CHỨC NĂNG: UPLOAD NOTE
// ---------------------------------------------------------

void ClientApp::UploadNote(TLSConnection conn) {
    if (authToken.empty()) {
        cerr << "[ERROR] Login required." << endl;
        return;
    }

    string filename;
    cout << "Enter filename path to upload: ";
    cin >> filename;

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        cerr << "[ERROR] Cannot open file: " << filename << endl;
        return;
    }

    std::vector<uint8_t> fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (fileContent.empty()) {
        cerr << "[ERROR] File is empty." << endl;
        return;
    }

    try {
        std::vector<uint8_t> noteKey = CryptoManager::generateRandomBytes(32);
        std::vector<uint8_t> iv;
        std::vector<uint8_t> tag;
        std::vector<uint8_t> cipherBytes;

        if (!CryptoManager::aesEncrypt(fileContent, noteKey, iv, tag, cipherBytes)) {
            cerr << "[ERROR] Encryption failed." << endl;
            return;
        }
        std::filesystem::path p(filename);
        string baseName = p.filename().string();

        json req;
        req["token"] = authToken;
        req["cipher_text"] = CryptoManager::base64Encode(cipherBytes);
        req["iv"] = CryptoManager::base64Encode(iv);
        req["tag"] = CryptoManager::base64Encode(tag);
        req["filename"] = baseName;

        if (!sendPacket(conn, (int)CommandType::UPLOAD_NOTE, req)) return;

        json res = receivePacket(conn);

        if (res.value("status", "") == "ok") {
            string noteId = res["noteId"];
            localKeys[noteId] = CryptoManager::base64Encode(noteKey);
            saveLocalKeys();

            cout << "[SUCCESS] Note uploaded with ID: " << noteId << endl;
        }
        else {
            cerr << "[FAILED] Upload error: " << res.value("message", "Unknown") << endl;
        }

    }
    catch (const std::exception& e) {
        cerr << "[ERROR] Processing error: " << e.what() << endl;
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


void ClientApp::loadLocalKeys() {
    if (std::filesystem::exists(KEY_STORE_FILE)) {
        try {
            std::ifstream f(KEY_STORE_FILE);
            json j; f >> j;
            localKeys = j.get<std::map<std::string, std::string>>();
        }
        catch (...) {}
    }
}

void ClientApp::saveLocalKeys() {
    std::ofstream f(KEY_STORE_FILE);
    json j(localKeys);
    f << j.dump(4);
    f.close();
}

// ---------------------------------------------------------
//              CHỨC NĂNG: LIỆT KÊ GHI CHÚ
// ---------------------------------------------------------

void ClientApp::ListNotes(TLSConnection conn) {
    if (authToken.empty()) {
        cerr << "[ERROR] Login required." << endl;
        return;
    }

    json req;
    req["token"] = authToken;

    if (!sendPacket(conn, (int)CommandType::GET_METADATA, req)) return;
    json res = receivePacket(conn);

    if (res.is_array()) {
        cout << "\n--- MY NOTES ---" << endl;
        printf("%-15s | %-25s\n", "Note ID", "Upload Time");
        cout << "---------------------------------------------" << endl;
        for (auto& item : res) {
            string id = item.value("noteId", "N/A");
            time_t upTime = item.value("uploadTime", 0);
            string timeStr = "Unknown";
            if (upTime > 0) {
                char buffer[26];
                ctime_r(&upTime, buffer);
                timeStr = buffer;
                if (!timeStr.empty() && timeStr.back() == '\n') timeStr.pop_back();
            }
            printf("%-15s | %-25s\n", id.c_str(), timeStr.c_str());
        }
        cout << "---------------------------------------------" << endl;
    }
    else {
        cout << "[ERROR] Failed to list notes." << endl;
    }
}


// ---------------------------------------------------------
//              CHỨC NĂNG: DOWNLOAD NOTE (OWNER)
// ---------------------------------------------------------
void ClientApp::DownloadNote(TLSConnection conn) {
    if (authToken.empty()) { cerr << "[ERROR] Login required." << endl; return; }

    string noteId;
    cout << "Enter Note ID: "; cin >> noteId;

    // Tìm key trong máy
    string keyB64 = localKeys.count(noteId) ? localKeys[noteId] : "";
    if (keyB64.empty()) {
        cout << "[WARN] Key not found locally. Enter Key (Base64): "; cin >> keyB64;
    }

    json req;
    req["token"] = authToken;
    req["noteId"] = noteId;

    if (!sendPacket(conn, (int)CommandType::DOWNLOAD_NOTE, req)) return;
    json res = receivePacket(conn);

    if (res.contains("cipher_text")) {
        try {
            vector<uint8_t> cipher = CryptoManager::base64Decode(res["cipher_text"]);
            vector<uint8_t> iv = CryptoManager::base64Decode(res["iv"]);
            vector<uint8_t> tag = CryptoManager::base64Decode(res["tag"]);
            vector<uint8_t> key = CryptoManager::base64Decode(keyB64);
            vector<uint8_t> plain;

            if (CryptoManager::aesDecrypt(cipher, key, iv, tag, plain)) {
                string originalName = res.value("filename", "unknown_share.bin");

                string saveDir = "downloads/";
                if (!currentUsername.empty()) {
                    saveDir = "client_data/" + currentUsername + "/downloads/";
                }

                if (!fs::exists(saveDir)) {
                    fs::create_directories(saveDir);
                }

                string outPath = saveDir + originalName;

                ofstream f(outPath, ios::binary);
                f.write((char*)plain.data(), plain.size());
                f.close();
                cout << "[SUCCESS] File saved as: " << outPath << endl;
            }
            else {
                cerr << "[ERROR] Decryption failed! Key incorrect?" << endl;
            }
        }
        catch (...) { cout << "[ERROR] Exception during decryption." << endl; }
    }
    else {
        cout << "[ERROR] " << res.value("message", "Failed to download") << endl;
    }
}



// ---------------------------------------------------------
//              Sare Note
// ---------------------------------------------------------
void ClientApp::ShareNote(TLSConnection conn) {
    if (authToken.empty()) { cout << "[ERROR] Login required." << endl; return; }
    if (private_key.empty()) { cout << "[ERROR] Private key missing. Cannot perform E2EE." << endl; return; }

    // 1. Chọn file và người nhận
    ListNotes(conn);
    string noteId, recipient;

    cout << "\n=== SHARE NOTE (End-to-End Encrypted) ===" << endl;
    cout << "Enter Note ID to share: "; cin >> noteId;
    cout << "Enter Recipient Username: "; cin >> recipient;

    // --- NHẬP METADATA ---
    int hours, views;
    cout << "Link expiration (hours): ";
    if (!(cin >> hours)) { // Validate input số
        cin.clear(); cin.ignore(1000, '\n'); hours = 24; // Mặc định 24h nếu nhập sai
    }

    cout << "Max views (e.g. 1): ";
    if (!(cin >> views)) {
        cin.clear(); cin.ignore(1000, '\n'); views = 1; // Mặc định 1 view nếu nhập sai
    }


    // 2. Tìm Note Key trong máy
    if (localKeys.find(noteId) == localKeys.end()) {
        cout << "[ERROR] Encryption Key for this note not found locally." << endl; return;
    }
    vector<uint8_t> noteKey = CryptoManager::base64Decode(localKeys[noteId]);

    // 3. Lấy Public Key của Người nhận (Recipient)
    json reqKey; reqKey["username"] = recipient;
    if (!sendPacket(conn, (int)CommandType::GET_PUBLIC_KEY, reqKey)) return;
    json resKey = receivePacket(conn);

    if (resKey.value("status", "") != "ok") {
        cout << "[ERROR] Recipient not found or has no public key." << endl; return;
    }
    vector<uint8_t> recipientPubKey = CryptoManager::base64Decode(resKey["public_key"]);

    // 4. E2EE: Tính Shared Secret và Mã hóa Note Key
    cout << "[INFO] Encrypting key for " << recipient << "..." << endl;
    vector<uint8_t> sharedSecret = CryptoManager::deriveSharedSecret(private_key, recipientPubKey);

    vector<uint8_t> encKey, iv, tag;
    CryptoManager::aesEncrypt(noteKey, sharedSecret, iv, tag, encKey);

    // 5. Gửi Metadata lên Server
    json reqShare;
    reqShare["token"] = authToken;
    reqShare["noteId"] = noteId;
    reqShare["recipient"] = recipient;
    reqShare["encrypted_key"] = CryptoManager::base64Encode(encKey);
    reqShare["iv"] = CryptoManager::base64Encode(iv);
    reqShare["tag"] = CryptoManager::base64Encode(tag);

    // --- GỬI DỮ LIỆU NGƯỜI DÙNG NHẬP ---
    reqShare["duration"] = hours * 3600; // Đổi giờ sang giây
    reqShare["max_views"] = views;
    // ------------------------------------

    if (!sendPacket(conn, (int)CommandType::SHARE_NOTE, reqShare)) return;
    json resShare = receivePacket(conn);

    if (resShare.value("status", "") == "ok") {
        string shareId = resShare["shareId"];
        cout << "\n[SUCCESS] Encrypted Link Created!" << endl;
        cout << "---------------------------------------------------" << endl;
        cout << "URL: securenote://" << shareId << endl;
        cout << "---------------------------------------------------" << endl;
        cout << "Settings: Expire in " << hours << "h, Max views: " << views << endl;
        cout << "Send this URL to user '" << recipient << "'." << endl;
    }
    else {
        cerr << "[FAILED] " << resShare.value("message", "Unknown error") << endl;
    }
}

// ---------------------------------------------------------
//              Download file từ URL
// ---------------------------------------------------------
void ClientApp::DownloadFromURL(TLSConnection conn) {
    if (authToken.empty()) { cout << "[ERROR] Login required to verify identity." << endl; return; }
    if (private_key.empty()) { cout << "[ERROR] Private key missing." << endl; return; }

    string url;
    cout << "Paste the URL (securenote://...): "; cin >> url;

    string prefix = "securenote://";
    size_t prefixPos = url.find(prefix);
    if (prefixPos == string::npos) {
        cerr << "[ERROR] Invalid URL format!" << endl; return;
    }
    string shareId = url.substr(prefix.length());

    // 1. Tải Metadata & Encrypted Key
    json req; req["shareId"] = shareId;
    if (!sendPacket(conn, (int)CommandType::DOWNLOAD_SHARED, req)) return;
    json res = receivePacket(conn);

    if (!res.contains("encrypted_key")) {
        cout << "[ERROR] Link invalid, expired or access denied." << endl; return;
    }

    try {
        string sender = res["sender"];
        cout << "[INFO] Note sent by: " << sender << endl;

        // 2. Lấy Public Key Sender
        json reqKey; reqKey["username"] = sender;
        if (!sendPacket(conn, (int)CommandType::GET_PUBLIC_KEY, reqKey)) return;
        json resKey = receivePacket(conn);
        vector<uint8_t> senderPubKey = CryptoManager::base64Decode(resKey["public_key"]);

        // 3. E2EE Decrypt Key
        vector<uint8_t> sharedSecret = CryptoManager::deriveSharedSecret(private_key, senderPubKey);
        vector<uint8_t> encKey = CryptoManager::base64Decode(res["encrypted_key"]);
        vector<uint8_t> kIv = CryptoManager::base64Decode(res["key_iv"]);
        vector<uint8_t> kTag = CryptoManager::base64Decode(res["key_tag"]);
        vector<uint8_t> noteKey;

        if (!CryptoManager::aesDecrypt(encKey, sharedSecret, kIv, kTag, noteKey)) {
            cout << "[ERROR] E2EE Decryption Failed! Wrong identity." << endl; return;
        }

        // 4. Decrypt Content
        vector<uint8_t> cipher = CryptoManager::base64Decode(res["cipher_text"]);
        vector<uint8_t> cIv = CryptoManager::base64Decode(res["iv"]);
        vector<uint8_t> cTag = CryptoManager::base64Decode(res["tag"]);
        vector<uint8_t> plain;

        if (CryptoManager::aesDecrypt(cipher, noteKey, cIv, cTag, plain)) {
            string originalName = res.value("filename", "unknown_share.bin");

            string saveDir = "downloads/";
            if (!currentUsername.empty()) {
                saveDir = "client_data/" + currentUsername + "/downloads/";
            }

            if (!fs::exists(saveDir)) {
                fs::create_directories(saveDir);
            }

            string outPath = saveDir + originalName;

            ofstream f(outPath, ios::binary);
            f.write((char*)plain.data(), plain.size());
            f.close();
            cout << "[SUCCESS] Decrypted & Saved to: " << outPath << endl;
        }
        else {
            cout << "[ERROR] Content Decryption Failed." << endl;
        }

    }
    catch (const std::exception& e) {
        cerr << "[ERROR] " << e.what() << endl;
    }
}


// ---------------------------------------------------------
//      Tạo workspace cho user
// ---------------------------------------------------------
void ClientApp::setupUserWorkspace(const std::string& username) {
    try {
        // Đường dẫn gốc: client_data/username
        std::string userRoot = "client_data/" + username;
        std::string downloadPath = userRoot + "/downloads";
        std::string dataPath = userRoot + "/data";

        // Tạo các thư mục (hàm create_directories sẽ không lỗi nếu thư mục đã tồn tại)
        if (!fs::exists(userRoot)) fs::create_directories(userRoot);
        if (!fs::exists(downloadPath)) fs::create_directories(downloadPath);
        if (!fs::exists(dataPath)) fs::create_directories(dataPath);

        std::cout << "[INFO] User workspace created at: " << userRoot << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed to create user directories: " << e.what() << std::endl;
    }
}