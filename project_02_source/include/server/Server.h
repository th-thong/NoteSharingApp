#ifndef SERVER_H
#define SERVER_H

#include "AuthManager.h"
#include "NoteManager.h"
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <winsock2.h>
typedef int SOCKET;
#else
typedef int SOCKET;
#endif

class Server {
private:
    int port;
    SOCKET serverSocket;
    AuthManager authManager;
    NoteManager noteManager;
    SSL_CTX* ctx;

    // Hàm khởi tạo SSL
    void initOpenssl();
    void cleanupOpenssl();
    SSL_CTX* createServerContext();
    void configureContext(SSL_CTX* ctx);

    void handleClient(SOCKET clientSocket);

    bool sendPacket(SSL* ssl, int cmd, const std::string& payload);

public:
    Server(int port);
    ~Server();
    void start();
};

#endif