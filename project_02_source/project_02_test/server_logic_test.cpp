#include <gtest/gtest.h>
#include "AuthManager.h"
#include "NoteManager.h"
#include <filesystem>
#include <fstream>
#include <string>
namespace fs = std::filesystem;

class ServerLogicTest : public ::testing::Test {
protected:
    const std::string TEST_ROOT = "server_data_test/";

    void SetUp() override {
        if (fs::exists(TEST_ROOT)) fs::remove_all(TEST_ROOT);
        fs::create_directories(TEST_ROOT);
    }

    void TearDown() override {
        fs::remove_all(TEST_ROOT);
    }
};

// --- 1. Test AuthManager ---
TEST_F(ServerLogicTest, UserRegistrationAndLogin) {
    AuthManager auth("server_data_test/");

    std::string user = "testuser";
    std::string pass = "password123";
    std::string pubKey = "dummy_public_key_base64";

    // 1. Đăng ký
    bool regResult = auth.registerUser(user, pass, pubKey);
    ASSERT_TRUE(regResult) << "Registration should succeed";

    // 2. Đăng ký trùng -> Fail
    bool regDuplicate = auth.registerUser(user, pass, pubKey);
    ASSERT_FALSE(regDuplicate) << "Duplicate user registration should fail";

    // 3. Đăng nhập đúng
    std::string token = auth.loginUser(user, pass);
    ASSERT_FALSE(token.empty()) << "Login should return a token";

    // 4. Đăng nhập sai
    std::string badToken = auth.loginUser(user, "wrongpass");
    ASSERT_TRUE(badToken.empty()) << "Login with wrong pass should fail";

    // 5. Validate Token
    std::string usernameFromToken = auth.validateToken(token);
    EXPECT_EQ(usernameFromToken, user);
}

// --- 2. Test NoteManager (Cơ bản) ---
TEST_F(ServerLogicTest, SaveAndGetNote) {
    NoteManager noteMgr(TEST_ROOT); 
    
    std::string owner = "userA";
    std::string content = "TestContent";
    
    // 1. Save 
    std::string noteId = noteMgr.saveNote(owner, content, "iv", "tag", "file.txt");
    ASSERT_FALSE(noteId.empty());

    // 2. Kiểm tra file vật lý ở đúng thư mục
    std::string expectedPath = TEST_ROOT + "notes/" + noteId + ".bin";
    ASSERT_TRUE(fs::exists(expectedPath)) << "File should exist in TEST directory";
    
    // 3. Kiểm tra không bị ghi nhầm sang thư mục thật
    std::string wrongPath = "server_data/notes/" + noteId + ".bin";
    ASSERT_FALSE(fs::exists(wrongPath)) << "File should NOT exist in PRODUCTION directory";
}

// --- 3. Test E2EE Sharing Logic ---
TEST_F(ServerLogicTest, CreateTargetedShare) {
    NoteManager noteMgr(TEST_ROOT);
    std::string sender = "Alice";
    std::string recipient = "Bob";
    
    // Tạo note gốc của Alice
    std::string noteId = noteMgr.saveNote(sender, "SecretData", "iv", "tag", "secret.txt");

    // 1. Tạo Share E2EE
    std::string encKey = "KeyEncryptedForBob";
    std::string shareId = noteMgr.createTargetedShare(
        noteId, sender, recipient, encKey, 
        "k_iv", "k_tag", 3600, 5
    );
    ASSERT_FALSE(shareId.empty());

    // 2. Bob lấy nội dung share
    std::string content, iv, tag, fname;
    ShareMetadata meta;
    
    bool shareRes = noteMgr.getSharedNoteContent(shareId, content, iv, tag, meta, fname);
    ASSERT_TRUE(shareRes);
    
    // Kiểm tra metadata E2EE trả về đúng không
    EXPECT_EQ(meta.senderUsername, sender);
    EXPECT_EQ(meta.recipientUsername, recipient);
    EXPECT_EQ(meta.encryptedKey, encKey);
    EXPECT_EQ(fname, "secret.txt");
}