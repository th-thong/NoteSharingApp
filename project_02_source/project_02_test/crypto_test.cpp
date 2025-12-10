#include <gtest/gtest.h>
#include "CryptoManager.h"
#include <vector>
#include <string>
#include <cstring>


// --- 1. Test Sinh số ngẫu nhiên ---
TEST(CryptoTest, GenerateRandomBytes) {
    // Kiểm tra độ dài
    auto bytes = CryptoManager::generateRandomBytes(32);
    ASSERT_EQ(bytes.size(), 32);

    // Kiểm tra tính ngẫu nhiên (xác suất trùng lặp cực thấp)
    auto bytes2 = CryptoManager::generateRandomBytes(32);
    ASSERT_NE(bytes, bytes2); 
}

// --- 2. Test Mã hóa/Giải mã AES-GCM ---
TEST(CryptoTest, AesEncryptionCorrectness) {
    std::string original = "Secret Note Content 123!";
    std::vector<uint8_t> plaintext(original.begin(), original.end());
    std::vector<uint8_t> key = CryptoManager::generateRandomBytes(32); // 256 bit key
    
    std::vector<uint8_t> iv, tag, ciphertext;

    // A. Mã hóa
    bool encryptStatus = CryptoManager::aesEncrypt(plaintext, key, iv, tag, ciphertext);
    ASSERT_TRUE(encryptStatus);
    ASSERT_FALSE(ciphertext.empty());
    ASSERT_EQ(iv.size(), 12); // GCM IV chuẩn 12 bytes
    ASSERT_EQ(tag.size(), 16); // GCM Tag chuẩn 16 bytes

    // B. Giải mã đúng key
    std::vector<uint8_t> decrypted;
    bool decryptStatus = CryptoManager::aesDecrypt(ciphertext, key, iv, tag, decrypted);
    ASSERT_TRUE(decryptStatus);
    
    std::string result(decrypted.begin(), decrypted.end());
    EXPECT_EQ(original, result);
}

// Test trường hợp bị giả mạo dữ liệu
TEST(CryptoTest, AesDecryptionTampered) {
    std::string original = "Data Integrity Check";
    std::vector<uint8_t> plaintext(original.begin(), original.end());
    std::vector<uint8_t> key = CryptoManager::generateRandomBytes(32);
    std::vector<uint8_t> iv, tag, ciphertext;

    CryptoManager::aesEncrypt(plaintext, key, iv, tag, ciphertext);

    // Tình huống 1: Sửa đổi Ciphertext
    ciphertext[0] ^= 0xFF; 
    std::vector<uint8_t> decrypted;
    bool status = CryptoManager::aesDecrypt(ciphertext, key, iv, tag, decrypted);
    EXPECT_FALSE(status) << "Should fail if ciphertext is modified";

    // Tình huống 2: Sai Tag xác thực
    ciphertext[0] ^= 0xFF; // Hoàn tác sửa ciphertext
    tag[0] ^= 0xFF;        // Sửa tag
    status = CryptoManager::aesDecrypt(ciphertext, key, iv, tag, decrypted);
    EXPECT_FALSE(status) << "Should fail if auth tag is wrong";
}

// --- 3. Test Diffie-Hellman Key Exchange ---
TEST(CryptoTest, DiffieHellmanExchange) {
    // User A sinh cặp khóa
    std::vector<uint8_t> pubA, privA;
    CryptoManager::generateDHKeyPair(pubA, privA);
    ASSERT_FALSE(pubA.empty());
    ASSERT_FALSE(privA.empty());

    // User B sinh cặp khóa
    std::vector<uint8_t> pubB, privB;
    CryptoManager::generateDHKeyPair(pubB, privB);

    // A tính Shared Secret (PrivA + PubB)
    std::vector<uint8_t> secretA = CryptoManager::deriveSharedSecret(privA, pubB);

    // B tính Shared Secret (PrivB + PubA)
    std::vector<uint8_t> secretB = CryptoManager::deriveSharedSecret(privB, pubA);

    // Hai secret phải giống hệt nhau (Đây là cơ sở của E2EE)
    ASSERT_EQ(secretA.size(), 32);
    ASSERT_EQ(secretB.size(), 32);
    EXPECT_EQ(secretA, secretB) << "Shared secrets must match";
}

// --- 4. Test Hashing Password & Base64 ---
TEST(CryptoTest, PasswordHashingAndBase64) {
    std::string password = "MySecurePassword";
    std::vector<uint8_t> salt, hash;

    // Hash lần 1
    CryptoManager::hashPasswordPBKDF2(password, salt, hash);
    
    // Test Base64 Encode/Decode luôn thể
    std::string b64Salt = CryptoManager::base64Encode(salt);
    std::string b64Hash = CryptoManager::base64Encode(hash);
    
    std::vector<uint8_t> decodedSalt = CryptoManager::base64Decode(b64Salt);
    std::vector<uint8_t> decodedHash = CryptoManager::base64Decode(b64Hash);
    
    ASSERT_EQ(salt, decodedSalt);
    ASSERT_EQ(hash, decodedHash);

    // Verify Password đúng
    bool valid = CryptoManager::verifyPasswordPBKDF2(password, decodedSalt, decodedHash);
    EXPECT_TRUE(valid);

    // Verify Password sai
    bool invalid = CryptoManager::verifyPasswordPBKDF2("WrongPass", decodedSalt, decodedHash);
    EXPECT_FALSE(invalid);
}