#include <gtest/gtest.h>
#include "CryptoManager.h"
#include <vector>
#include <string>

using namespace std;

// Secure RNG Uniqueness
TEST(CryptoTest, SecureRandomGeneration) {
    auto key1 = CryptoManager::generateRandomBytes(32);
    auto key2 = CryptoManager::generateRandomBytes(32);
    ASSERT_EQ(key1.size(), 32);
    ASSERT_NE(key1, key2) << "RNG must not repeat values";
}

// AES-GCM Encryption/Decryption
TEST(CryptoTest, AesEncryptionCorrectness) {
    string original = "Sensitive Data Content 123";
    vector<uint8_t> plain(original.begin(), original.end());
    vector<uint8_t> key = CryptoManager::generateRandomBytes(32);
    vector<uint8_t> iv, tag, cipher;

    ASSERT_TRUE(CryptoManager::aesEncrypt(plain, key, iv, tag, cipher));
    
    vector<uint8_t> decrypted;
    ASSERT_TRUE(CryptoManager::aesDecrypt(cipher, key, iv, tag, decrypted));
    
    string result(decrypted.begin(), decrypted.end());
    EXPECT_EQ(original, result);
}

// Data Integrity & Wrong Key
TEST(CryptoTest, AesIntegrityAndSecurity) {
    vector<uint8_t> plain(10, 'A');
    vector<uint8_t> key = CryptoManager::generateRandomBytes(32);
    vector<uint8_t> iv, tag, cipher;
    CryptoManager::aesEncrypt(plain, key, iv, tag, cipher);

    vector<uint8_t> decrypted;

    // Sửa đổi Ciphertext (Tamper)
    cipher[0] ^= 0xFF; 
    EXPECT_FALSE(CryptoManager::aesDecrypt(cipher, key, iv, tag, decrypted)) 
        << "Decryption MUST fail if ciphertext is modified";
    
    // Hoàn tác sửa đổi để test tiếp
    cipher[0] ^= 0xFF; 

    // Sửa đổi Tag
    tag[0] ^= 0xFF;    
    EXPECT_FALSE(CryptoManager::aesDecrypt(cipher, key, iv, tag, decrypted)) 
        << "Decryption MUST fail if auth tag is wrong";

    // Sai Key
    tag[0] ^= 0xFF; // Hoàn tác sửa tag
    vector<uint8_t> wrongKey = CryptoManager::generateRandomBytes(32);
    EXPECT_FALSE(CryptoManager::aesDecrypt(cipher, wrongKey, iv, tag, decrypted)) 
        << "Decryption MUST fail with wrong key";
}

// ECDH Key Exchange
TEST(CryptoTest, DiffieHellmanExchange) {
    vector<uint8_t> pubA, privA, pubB, privB;
    CryptoManager::generateDHKeyPair(pubA, privA);
    CryptoManager::generateDHKeyPair(pubB, privB);

    auto secretA = CryptoManager::deriveSharedSecret(privA, pubB);
    auto secretB = CryptoManager::deriveSharedSecret(privB, pubA);

    ASSERT_EQ(secretA, secretB) << "Shared secrets must match";
}

// Password Hashing
TEST(CryptoTest, PasswordHashingPBKDF2) {
    string password = "MySecurePassword";
    vector<uint8_t> salt, hash;

    CryptoManager::hashPasswordPBKDF2(password, salt, hash);
    
    // Verify đúng
    EXPECT_TRUE(CryptoManager::verifyPasswordPBKDF2(password, salt, hash));
    
    // Verify sai
    EXPECT_FALSE(CryptoManager::verifyPasswordPBKDF2("WrongPass", salt, hash));
}