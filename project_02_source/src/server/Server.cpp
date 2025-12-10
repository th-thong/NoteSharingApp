#include "Server.h"
#include "Protocol.h"
#include "Utils.h"
#include "CryptoManager.h"
#include "NoteManager.h"

#include <iostream>
#include <thread>
#include <vector>
#include <cstring>
#include <nlohmann/json.hpp>
#include <fstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#define close closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

using json = nlohmann::json;

// Hàm khởi tạo OpenSSL
void Server::initOpenssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Hàm dọn dẹp OpenSSL
void Server::cleanupOpenssl() {
    EVP_cleanup();
}

// Tạo SSL context cho server
SSL_CTX* Server::createServerContext() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// Cấu hình SSL context với chứng chỉ và khóa riêng
void Server::configureContext(SSL_CTX* ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "../server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "../server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// Constructor và Destructor của Server
Server::Server(int port) : port(port), serverSocket(INVALID_SOCKET) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    initOpenssl();
    ctx = createServerContext();
    configureContext(ctx);
}

Server::~Server() {
    if (serverSocket != INVALID_SOCKET) {
        close(serverSocket);
    }
    SSL_CTX_free(ctx);
    cleanupOpenssl();
#ifdef _WIN32
    WSACleanup();
#endif
}


// Hàm khởi động server và lắng nghe kết nối
void Server::start() {
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "[ERROR] Cannot create socket" << std::endl;
        return;
    }

    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Bind failed" << std::endl;
        return;
    }

    if (listen(serverSocket, 10) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Listen failed" << std::endl;
        return;
    }

    std::cout << "[INFO] Server started on port " << port << " (SSL/TLS Enabled)..." << std::endl;

    while (true) {
        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        SOCKET clientSock = accept(serverSocket, (sockaddr*)&clientAddr, &clientLen);

        if (clientSock == INVALID_SOCKET) {
            continue;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
        std::cout << "[INFO] New connection from: " << clientIP << std::endl;

        std::thread(&Server::handleClient, this, clientSock).detach();
    }
}

// Hàm gửi gói tin qua SSL
bool Server::sendPacket(SSL* ssl, int cmd, const std::string& payload) {
    PacketHeader header;
    header.cmd = (CommandType)cmd;
    header.payloadSize = (uint32_t)payload.size();
    memset(header.token, 0, sizeof(header.token));

    if (SSL_write(ssl, &header, sizeof(PacketHeader)) <= 0) return false;

    if (header.payloadSize > 0) {
        if (SSL_write(ssl, payload.c_str(), header.payloadSize) <= 0) return false;
    }
    return true;
}

// Hàm xử lý kết nối từ client
void Server::handleClient(SOCKET clientSock) {
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientSock);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(clientSock);
        return;
    }

    while (true) {
        PacketHeader header;

        int bytesRead = SSL_read(ssl, &header, sizeof(PacketHeader));
        if (bytesRead <= 0) {
            std::cout << "[INFO] Client disconnected." << std::endl;
            break;
        }

        std::string payloadData;
        if (header.payloadSize > 0) {
            std::vector<char> buffer(header.payloadSize + 1);
            int totalReceived = 0;
            while (totalReceived < (int)header.payloadSize) {
                int r = SSL_read(ssl, buffer.data() + totalReceived, header.payloadSize - totalReceived);
                if (r <= 0) break;
                totalReceived += r;
            }
            buffer[header.payloadSize] = '\0';
            payloadData = std::string(buffer.data(), header.payloadSize);
        }

        std::string responsePayload = "";
        CommandType responseCmd = CommandType::CMD_SUCCESS;

        try {
            switch (header.cmd) {

            case CommandType::REGISTER: {
                auto j = json::parse(payloadData);
                if (authManager.registerUser(j["username"], j["password"], j["public_key"])) {
                    responsePayload = "{\"status\": \"ok\"}";
                }
                else {
                    responseCmd = CommandType::CMD_ERROR;
                    responsePayload = "{\"status\": \"error\", \"message\": \"User exists\"}";
                }
                break;
            }

            case CommandType::LOGIN: {
                auto j = json::parse(payloadData);
                std::string token = authManager.loginUser(j["username"], j["password"]);
                if (!token.empty()) {
                    json res;
                    res["token"] = token;
                    res["refreshToken"] = token;
                    responsePayload = res.dump();
                }
                else {
                    responseCmd = CommandType::CMD_ERROR;
                    responsePayload = "{\"token\": null}";
                }
                break;
            }

            case CommandType::GET_METADATA: {
                auto j = json::parse(payloadData);
                std::string token = j["token"];
                std::string username = authManager.validateToken(token);

                if (username.empty()) {
                    responseCmd = CommandType::CMD_ERROR;
                    responsePayload = "{\"message\": \"Unauthorized\"}";
                }
                else {
                    // Lấy danh sách note
                    auto notes = noteManager.getNotesByUser(username);
                    json noteList = json::array();
                    for (const auto& n : notes) {
                        noteList.push_back(NoteMetadataToJson(n));
                    }
                    responsePayload = noteList.dump();
                }
                break;
            }

            case CommandType::DELETE_NOTE: {
                try {
                    auto j = json::parse(payloadData);
                    std::string token = j.value("token", "");
                    std::string noteId = j.value("noteId", "");

                    // 1. Xác thực người dùng từ Token
                    std::string username = authManager.validateToken(token);

                    if (username.empty()) {
                        responseCmd = CommandType::CMD_ERROR;
                        responsePayload = "{\"status\": \"error\", \"message\": \"Unauthorized\"}";
                    }
                    else {
                        // 2. Gọi NoteManager để xóa
                        if (noteManager.deleteNote(noteId, username)) {
                            // Xóa thành công
                            responsePayload = "{\"status\": \"ok\", \"message\": \"Note deleted successfully\"}";
                        }
                        else {
                            // Xóa thất bại (do không tìm thấy note hoặc không phải chủ sở hữu)
                            responseCmd = CommandType::CMD_ERROR;
                            responsePayload = "{\"status\": \"error\", \"message\": \"Delete failed. Note not found or permission denied.\"}";
                        }
                    }
                }
                catch (const std::exception& e) {
                    responseCmd = CommandType::CMD_ERROR;
                    responsePayload = "{\"status\": \"error\", \"message\": \"Invalid Request Format\"}";
                }
                break;
            }

            case CommandType::UPLOAD_NOTE: {
                auto j = json::parse(payloadData);
                std::string username = authManager.validateToken(j["token"]);
                if (username.empty()) {
                    responseCmd = CommandType::CMD_ERROR;
                    responsePayload = "{\"message\": \"Unauthorized\"}";
                    break;
                }

                std::string filename = j.value("filename", "unknown.bin");
                // Lưu note (raw storage)
                std::string noteId = noteManager.saveNote(
                    username, j["cipher_text"],
                    j["iv"], j["tag"],
                    filename
                );

                if (!noteId.empty())
                    responsePayload = "{\"status\":\"ok\", \"noteId\":\"" + noteId + "\"}";
                else {
                    responseCmd = CommandType::CMD_ERROR;
                    responsePayload = "{\"status\":\"error\"}";
                }
                break;
            }

			// Share NOTE (Tạo liên kết chia sẻ E2EE)
            case CommandType::SHARE_NOTE: {
                auto j = json::parse(payloadData);
                std::string sender = authManager.validateToken(j["token"]);
                if (sender.empty()) {
                    responseCmd = CommandType::CMD_ERROR;
                    responsePayload = "{\"message\": \"Unauthorized\"}";
                    break;
                }

                // Gọi hàm tạo share trong NoteManager
                std::string shareId = noteManager.createTargetedShare(
                    j["noteId"], sender,
                    j["recipient"], j["encrypted_key"],
                    j["iv"], j["tag"],
                    j["duration"], j["max_views"]
                );

                if (!shareId.empty())
                    responsePayload = "{\"status\":\"ok\", \"shareId\":\"" + shareId + "\"}";
                else
                    responsePayload = "{\"message\": \"Failed to share (Invalid ID or Permission)\"}";
                break;
            }

            case CommandType::DOWNLOAD_SHARED: {
                auto j = json::parse(payloadData);
                std::string shareId = j["shareId"];

                std::string content, iv, tag, filename;
                ShareMetadata shareMeta;

                if (noteManager.getSharedNoteContent(shareId, content, iv, tag, shareMeta, filename)) {
                    json res;
                    // Trả về Content đã mã hóa
                    res["cipher_text"] = CryptoManager::base64Encode(std::vector<uint8_t>(content.begin(), content.end()));
                    res["iv"] = iv;
                    res["tag"] = tag;

                    // Trả về Metadata E2EE để Client tự giải mã
                    res["sender"] = shareMeta.senderUsername;
                    res["encrypted_key"] = shareMeta.encryptedKey;
                    res["key_iv"] = shareMeta.keyIv;
                    res["key_tag"] = shareMeta.keyTag;
                    res["filename"] = filename;

                    responsePayload = res.dump();
                }
                else {
                    responseCmd = CommandType::CMD_ERROR;
                    responsePayload = "{\"message\": \"Link invalid, expired, or max views reached\"}";
                }
                break;
            }


            case CommandType::DOWNLOAD_NOTE: {
                auto j = json::parse(payloadData);
                std::string token = j["token"]; // Cần token để xác thực chủ sở hữu
                std::string noteId = j["noteId"];

                std::string username = authManager.validateToken(token);

                if (username.empty()) {
                    responseCmd = CommandType::CMD_ERROR;
                    responsePayload = "{\"message\": \"Unauthorized\"}";
                    break;
                }

                std::string content, iv, tag, filename;
                // Gọi hàm getNoteContent (chỉ lấy storage)
                if (noteManager.getNoteContent(noteId, content, iv, tag, filename)) {
                    json res;
                    res["cipher_text"] = CryptoManager::base64Encode(std::vector<uint8_t>(content.begin(), content.end()));
                    res["iv"] = iv;
                    res["tag"] = tag;
                    res["filename"] = filename;
                    responsePayload = res.dump();
                }
                else {
                    responseCmd = CommandType::CMD_ERROR;
                    responsePayload = "{\"message\": \"Note not found\"}";
                }
                break;
            }

            case CommandType::GET_PUBLIC_KEY: {
                auto j = json::parse(payloadData);
                std::string targetUser = j["username"];
                std::string pubKey = authManager.getUserPublicKey(targetUser);

                if (!pubKey.empty()) {
                    responsePayload = "{\"status\":\"ok\", \"public_key\":\"" + pubKey + "\"}";
                }
                else {
                    responseCmd = CommandType::CMD_ERROR;
                    responsePayload = "{\"message\": \"User not found\"}";
                }
                break;
            }



            default:
                responseCmd = CommandType::CMD_ERROR;
                responsePayload = "Unknown command";
                break;
            }
        }
        catch (const std::exception& e) {
            responseCmd = CommandType::CMD_ERROR;
            responsePayload = std::string("{\"error\": \"") + e.what() + "\"}";
        }

        // Ép kiểu enum về int khi gọi sendPacket
        sendPacket(ssl, (int)responseCmd, responsePayload);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(clientSock);
}