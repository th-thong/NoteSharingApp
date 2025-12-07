#include "ClientApp.h"

ClientApp::ClientApp(){

}

ClientApp::~ClientApp(){

}

TLSConnection ClientApp::connectServer(const std::string &ip, int port){
    //Tạo socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0){
        std::cerr << "error creating socket" << std::endl;
        return {NULL, 0, NULL};
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);

    //Kết nối đến server
    if(connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr) < 0)){
        std::cerr << "error connect to server" << std::endl;
        close(sockfd);
        return {NULL, 0, NULL};
    }

    //Thiết lập TLS
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        std::cerr << "TLS handshake failed\n";
        return {NULL, 0, NULL};
    }

    return TLSConnection{ssl, sockfd, ctx};
}



void ClientApp::menu(){
    std::cout << "1.Login\n";
    std::cout << "2.Register\n";
    std::cout << "3.Upload note\n";
    std::cout << "0.exit\n";
}

void ClientApp::handleEvents(){
    std::string server_ip;
    int port;
    std::cout << "Enter server IP:";
    std::cin >> server_ip;
    std::cout << "Enter port:";
    std::cin >> port;

    TLSConnection conn = connectServer(server_ip, port);

    menu();
    int choice = 1;
    while (choice > 0){
        std::cout << "Choose an option:\n";
        std::cin >> choice;
        switch(choice){ 
            case 1:
                Login(conn);
                break;
            case 2:
                Register(conn);
                break;
            case 3:
                UploadNote(conn);
                break;
            default:
                break;
        }
    }

    SSL_shutdown(conn.ssl);
    SSL_free(conn.ssl);
    SSL_CTX_free(conn.ctx);
    close(conn.sockfd);
}

void ClientApp::Login(TLSConnection conn){
    //Nhập username, password
    std::string username, password;
    std::cout << "Enter username:";
    std::cin >> username;
    std::cout << "Enter password:";
    std::cin >> password;

    //Tạo JSON request
    json req;
    req["action"] = "login";
    req["username"] = username;
    req["password"] = password;
    std::string req_str = req.dump();

    //Gửi request đến server
    SSL_write(conn.ssl, req_str.c_str(), req_str.size());

    //Nhận phản hồi từ server
    char buf[4096];
    SSL_read(conn.ssl, buf, sizeof(buf));

    //Xử lý phản hồi
    std::string response(buf);
    json res = json::parse(response);

    if(res["token"] == NULL){
        std::cerr << "Login failed" << std::endl;
        return;
    }

    authToken = res["token"];
    refreshToken = res["refreshToken"];

    std::cout << "Login successfully" << std::endl;
}
        
void ClientApp::Register(TLSConnection conn){
     //Nhập username, password
    std::string username, password;
    std::cout << "Enter username:";
    std::cin >> username;
    std::cout << "Enter password:";
    std::cin >> password;
    CryptoManager::generateDHKeyPair(public_key, private_key);

    //Chuyển public key sang string 
    std::string pubkeyStr = CryptoManager::base64Encode(public_key);

    //Tạo JSON request
    json req;
    req["action"] = "register";
    req["username"] = username;
    req["password"] = password;
    req["public_key"] = pubkeyStr;
    std::string req_str = req.dump();

    //Gửi request đến server
    SSL_write(conn.ssl, req_str.c_str(), req_str.size());

    //Nhận phản hồi từ server
    char buf[4096];
    SSL_read(conn.ssl, buf, sizeof(buf));

    //Xử lý phản hồi
    std::string response(buf);
    json res = json::parse(response);
    if(res["status" != "ok"]){
        std::cerr << "Register failed" << std::endl;
        return;
    }
    std::cout << "Register successfully" << std::endl;
}

std::string ClientApp::getNote(const char* filename){
    std::ifstream ifs(filename);
    if(!ifs.is_open()){
        std::cout << "Error opening file" << std::endl;
        return "";
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    return buffer.str();
}

void ClientApp::UploadNote(TLSConnection conn){
    std::string filename;
    std::string noteContent;
    std::cout << "Enter filename to upload:";
    std::cin >> filename;

    //Đọc nội dung file 
    
    noteContent = getNote(filename.c_str());

    //Sinh Notekey ngẫu nhiên
    std::vector<std::uint8_t> noteKey = CryptoManager::generateRandomBytes(32); //AES-256

    //Lưu Note key vào map
    noteKeys[filename] = CryptoManager::base64Encode(noteKey);

    //Chuyển nội dung file sang vector bytes
    std::vector<uint8_t> plainBytes = CryptoManager::base64Decode(noteContent);
    std::vector<uint8_t> iv, tag, cipherBytes;
    
    //mã hóa nội dung file
    if(!CryptoManager::aesEncrypt(plainBytes, noteKey, iv, tag, cipherBytes)){
        std::cout << "Error encrypting note" << std::endl;
        return;
    }

    //Tạo JSON request
    json req;
    req["action"] = "upload_note";
    req["filename"] = filename;
    req["cipher_text"] = CryptoManager::base64Encode(cipherBytes); //Chuyển thành string để gửi
    req["iv"] = CryptoManager::base64Encode(iv);
    req["tag"] = CryptoManager::base64Encode(tag);
    req["token"] = authToken;

    std::string req_str = req.dump();



    //Gửi request đến server
    SSL_write(conn.ssl, req_str.c_str(), req_str.size());

    //Nhận phản hồi từ server
    char buf[4096];
    SSL_read(conn.ssl, buf, sizeof(buf));

    //Xử lý phản hồi
    std::string response(buf);
    json res = json::parse(response);
    if(res["status" != "ok"]){
        std::cout << "Upload failed" << std::endl;
        return;
    }
    std::cout << "Upload successfully" << std::endl;
}
        