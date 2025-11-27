#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include <string>
#include <vector>
// Include OpenSSL headers here

class CryptoManager {
public:
    // --- Hashing & Password (cho Auth) ---
    // Sử dụng SHA-256 hoặc Argon2 + Salt
    static std::string hashPassword(const std::string& password, const std::string& salt);
    static std::string generateSalt();
    
    // --- AES Encryption (cho Client-side Encryption) ---
    // Sử dụng AES-256-GCM hoặc CBC. GCM được khuyến khích để đảm bảo tính toàn vẹn.
    // Trả về struct chứa Ciphertext và IV (Initialization Vector)
    static std::vector<unsigned char> encryptAES(const std::string& plaintext, const std::string& key);
    static std::string decryptAES(const std::vector<unsigned char>& ciphertext, const std::string& key);
    
    // Tạo khóa ngẫu nhiên cho mỗi ghi chú (256 bit)
    static std::string generateRandomKey();

    // --- Key Exchange (cho End-to-End Sharing) ---
    // Sử dụng Diffie-Hellman để tạo Shared Secret giữa 2 user
    struct DHKeys {
        std::string publicKey;
        std::string privateKey;
    };
    static DHKeys generateDHKeys();
    static std::string computeSharedSecret(const std::string& myPrivateKey, const std::string& peerPublicKey);
};

#endif