#include "Server.h"
#include "Protocol.h"
#include "Utils.h"

#include <iostream>
#include <thread>
#include <vector>
#include <cstring>
#include <nlohmann/json.hpp>

// --- Cấu hình Cross-Platform (Windows/Linux) ---
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
    typedef int SOCKET;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif

using json = nlohmann::json;

// Constructor
Server::Server(int port) : port(port), serverSocket(INVALID_SOCKET) {
    // Khởi tạo thư viện Socket nếu là Windows
    #ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    #endif
}

// Destructor
Server::~Server() {
    if (serverSocket != INVALID_SOCKET) {
        close(serverSocket);
    }
    #ifdef _WIN32
        WSACleanup();
    #endif
}

// Hàm khởi động Server
void Server::start() {
    // 1. Tạo Socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "[ERROR] Cannot create socket" << std::endl;
        return;
    }

    // 2. Cấu hình Socket (Tránh lỗi "Address already in use" khi restart nhanh)
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    // 3. Bind vào Port
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Lắng nghe mọi IP
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Bind failed. Port " << port << " may be in use." << std::endl;
        return;
    }

    // 4. Listen
    if (listen(serverSocket, 10) == SOCKET_ERROR) { // Hàng đợi tối đa 10
        std::cerr << "[ERROR] Listen failed" << std::endl;
        return;
    }

    std::cout << "[INFO] Server started on port " << port << "..." << std::endl;

    // 5. Vòng lặp chấp nhận kết nối
    while (true) {
        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        SOCKET clientSock = accept(serverSocket, (sockaddr*)&clientAddr, &clientLen);

        if (clientSock == INVALID_SOCKET) {
            std::cerr << "[WARN] Accept failed" << std::endl;
            continue;
        }

        // Lấy IP Client để log
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
        std::cout << "[INFO] New connection from: " << clientIP << std::endl;

        // 6. Tạo luồng riêng (Thread) để xử lý Client này
        // detach() để luồng chạy ngầm, không chặn vòng lặp chính
        std::thread(&Server::handleClient, this, clientSock).detach();
    }
}

// Hàm gửi gói tin phản hồi về Client
bool Server::sendPacket(SOCKET sock, CommandType cmd, const std::string& payload) {
    PacketHeader header;
    header.cmd = cmd;
    header.payloadSize = (uint32_t)payload.size();
    memset(header.token, 0, sizeof(header.token)); // Token phản hồi thường để trống

    // Gửi Header
    if (send(sock, (char*)&header, sizeof(PacketHeader), 0) <= 0) return false;
    
    // Gửi Payload (nếu có)
    if (header.payloadSize > 0) {
        if (send(sock, payload.c_str(), header.payloadSize, 0) <= 0) return false;
    }
    return true;
}

// Logic chính xử lý từng Client
void Server::handleClient(SOCKET clientSock) {
    while (true) {
        PacketHeader header;
        
        // 1. Nhận Header
        int bytesRead = recv(clientSock, (char*)&header, sizeof(PacketHeader), 0);
        if (bytesRead <= 0) {
            std::cout << "[INFO] Client disconnected." << std::endl;
            break; // Ngắt kết nối
        }

        // 2. Nhận Payload (nếu có)
        std::string payloadData;
        if (header.payloadSize > 0) {
            std::vector<char> buffer(header.payloadSize + 1);
            int totalReceived = 0;
            // Loop recv để đảm bảo nhận đủ byte (TCP stream)
            while (totalReceived < (int)header.payloadSize) {
                int r = recv(clientSock, buffer.data() + totalReceived, header.payloadSize - totalReceived, 0);
                if (r <= 0) break;
                totalReceived += r;
            }
            buffer[header.payloadSize] = '\0';
            payloadData = std::string(buffer.data(), header.payloadSize);
        }

        // 3. Xử lý lệnh (Switch Case)
        std::string responsePayload = "";
        CommandType responseCmd = CommandType::CMD_SUCCESS;

        try {
            switch (header.cmd) {
                case CommandType::REGISTER: {
                    auto j = json::parse(payloadData);
                    // Gọi AuthManager
                    if (authManager.registerUser(j["username"], j["password"], j["public_key"])) {
                        responsePayload = "Register success!";
                    } else {
                        responseCmd = CommandType::CMD_ERROR;
                        responsePayload = "Username already exists.";
                    }
                    break;
                }

                case CommandType::LOGIN: {
                    auto j = json::parse(payloadData);
                    std::string token = authManager.loginUser(j["username"], j["password"]);
                    if (!token.empty()) {
                        json res;
                        res["token"] = token;
                        responsePayload = res.dump();
                    } else {
                        responseCmd = CommandType::CMD_ERROR;
                        responsePayload = "Invalid username or password.";
                    }
                    break;
                }

                case CommandType::UPLOAD_NOTE: {
                    // Xác thực Token trước
                    std::string username = authManager.validateToken(header.token);
                    if (username.empty()) {
                        responseCmd = CommandType::CMD_ERROR;
                        responsePayload = "Unauthorized / Token expired.";
                        break;
                    }

                    auto j = json::parse(payloadData);
                    // Gọi NoteManager lưu file
                    std::string noteId = noteManager.saveNote(
                        username, 
                        j["content_hex"], 
                        j["duration"], 
                        j["max_views"]
                    );
                    
                    if (!noteId.empty()) {
                        json res;
                        res["note_id"] = noteId;
                        responsePayload = res.dump();
                    } else {
                        responseCmd = CommandType::CMD_ERROR;
                        responsePayload = "Failed to save note.";
                    }
                    break;
                }

                case CommandType::DOWNLOAD_NOTE: {
                    auto j = json::parse(payloadData);
                    std::string noteId = j["note_id"];
                    std::string encryptedContent;
                    
                    // Gọi NoteManager lấy file (đã check hết hạn bên trong)
                    if (noteManager.getNote(noteId, encryptedContent)) {
                        json res;
                        res["content_hex"] = encryptedContent;
                        responsePayload = res.dump();
                        responseCmd = CommandType::CMD_DATA;
                    } else {
                        responseCmd = CommandType::CMD_ERROR;
                        responsePayload = "Note not found or expired.";
                    }
                    break;
                }
                
                // TODO: Thêm các case SHARE_REQUEST_KEY tại đây...

                default:
                    responseCmd = CommandType::CMD_ERROR;
                    responsePayload = "Unknown command.";
                    break;
            }
        } catch (const std::exception& e) {
            responseCmd = CommandType::CMD_ERROR;
            responsePayload = std::string("Server Error: ") + e.what();
        }

        // 4. Gửi phản hồi về Client
        sendPacket(clientSock, responseCmd, responsePayload);
    }

    close(clientSock);
}