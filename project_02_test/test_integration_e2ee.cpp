#include <gtest/gtest.h>
#include "AuthManager.h"
#include "NoteManager.h"
#include "CryptoManager.h"
#include <filesystem>

namespace fs = std::filesystem;
using namespace std;

class IntegrationTest : public ::testing::Test {
protected:
    const string TEST_ROOT = "server_data_test/";
    void SetUp() override {
        if (fs::exists(TEST_ROOT)) fs::remove_all(TEST_ROOT);
        fs::create_directories(TEST_ROOT + "user");
        fs::create_directories(TEST_ROOT + "note");
        fs::create_directories(TEST_ROOT + "shares");
    }
};

// Full E2EE Sharing Flow
TEST_F(IntegrationTest, FullE2EEFlow) {
    AuthManager auth(TEST_ROOT);
    NoteManager noteMgr(TEST_ROOT);

    // 1. Setup Alice & Bob (Sinh Key thật)
    vector<uint8_t> pubA, privA, pubB, privB;
    CryptoManager::generateDHKeyPair(pubA, privA);
    CryptoManager::generateDHKeyPair(pubB, privB);

    auth.registerUser("Alice", "p", CryptoManager::base64Encode(pubA));
    auth.registerUser("Bob", "p", CryptoManager::base64Encode(pubB));

    // 2. Alice (Sender) chuẩn bị gửi
    // 2a. Lấy PubKey Bob từ Server
    string bobPubStr = auth.getUserPublicKey("Bob");
    auto bobPub = CryptoManager::base64Decode(bobPubStr);
    
    // 2b. Tính Secret
    auto secretA = CryptoManager::deriveSharedSecret(privA, bobPub);

    // 2c. Mã hóa Note Key (Giả lập note key ngẫu nhiên)
    auto realNoteKey = CryptoManager::generateRandomBytes(32);
    vector<uint8_t> encKey, iv, tag;
    CryptoManager::aesEncrypt(realNoteKey, secretA, iv, tag, encKey);

    // 2d. Upload & Share
    string noteId = noteMgr.saveNote("Alice", "EncryptedContent", "Iv", "Tag", "doc.pdf");
    string shareId = noteMgr.createTargetedShare(
        noteId, "Alice", "Bob",
        CryptoManager::base64Encode(encKey),
        CryptoManager::base64Encode(iv),
        CryptoManager::base64Encode(tag), 3600, 5
    );

    // 3. Bob (Recipient) nhận
    // 3a. Tải Metadata
    string c, nIv, nTag, f; ShareMetadata meta;
    ASSERT_TRUE(noteMgr.getSharedNoteContent(shareId, c, nIv, nTag, meta, f));

    // 3b. Lấy PubKey Alice
    string alicePubStr = auth.getUserPublicKey("Alice");
    auto alicePub = CryptoManager::base64Decode(alicePubStr);

    // 3c. Tính Secret
    auto secretB = CryptoManager::deriveSharedSecret(privB, alicePub);
    ASSERT_EQ(secretA, secretB); // Secret phải khớp

    // 3d. Giải mã Note Key
    vector<uint8_t> decryptedKey;
    auto kIv = CryptoManager::base64Decode(meta.keyIv);
    auto kTag = CryptoManager::base64Decode(meta.keyTag);
    auto kEnc = CryptoManager::base64Decode(meta.encryptedKey);

    bool success = CryptoManager::aesDecrypt(kEnc, secretB, kIv, kTag, decryptedKey);
    
    ASSERT_TRUE(success) << "Bob failed to decrypt key";
    ASSERT_EQ(decryptedKey, realNoteKey) << "Key integrity check passed";
}