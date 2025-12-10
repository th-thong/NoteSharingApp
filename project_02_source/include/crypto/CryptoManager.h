#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include <vector>
#include <string>
#include <cstdint> // Cho uint8_t
#include <cstddef> // Cho size_t

class CryptoManager {
private:
    CryptoManager() = delete;
public:

    // 1. Hàm bổ trợ
    static std::vector<std::uint8_t> generateRandomBytes(size_t size);

    // 2. PBKDF2
    static void hashPasswordPBKDF2(
        const std::string& password,
        std::vector<std::uint8_t>& saltOut,
        std::vector<std::uint8_t>& hashOut);
    static bool verifyPasswordPBKDF2(
        const std::string& password,
        const std::vector<std::uint8_t>& storedSalt,
        const std::vector<std::uint8_t>& storedHash);

    // 3. Diffie-Hellman
    static void generateDHKeyPair(
        std::vector<std::uint8_t>& publicKeyOut,
        std::vector<std::uint8_t>& privateKeyOut);

    static std::vector<uint8_t> deriveSharedSecret(
        const std::vector<uint8_t>& myPrivateKey,
        const std::vector<uint8_t>& peerPublicKey
    );

    // 4. AES-GCM Encrypt/Decrypt
    static bool aesEncrypt(
        const std::vector<std::uint8_t>& plaintext,
        const std::vector<std::uint8_t>& aesKey,
        std::vector<std::uint8_t>& ivOut,
        std::vector<std::uint8_t>& tagOut,
        std::vector<std::uint8_t>& ciphertextOut);
    static bool aesDecrypt(
        const std::vector<std::uint8_t>& ciphertext,
        const std::vector<std::uint8_t>& aesKey,
        const std::vector<std::uint8_t>& iv,
        const std::vector<std::uint8_t>& tag,
        std::vector<std::uint8_t>& plaintextOut);

    // 5. Trao đổi khoá
    static bool encryptAESKeyForRecipient(
        const std::vector<std::uint8_t>& aesKey,
        const std::vector<std::uint8_t>& sharedSecret,
        std::vector<std::uint8_t>& encryptedKeyOut);
    static bool decryptAESKeyFromSender(
        const std::vector<std::uint8_t>& encryptedKey,
        const std::vector<std::uint8_t>& sharedSecret,
        std::vector<std::uint8_t>& aesKeyOut);

    // 6. Base64 Encoding/Decoding
    static std::string base64Encode(const std::vector<std::uint8_t>& data);
    static std::vector<std::uint8_t> base64Decode(const std::string& encoded);


};
#endif