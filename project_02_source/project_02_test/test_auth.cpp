#include <gtest/gtest.h>
#include "AuthManager.h"
#include <filesystem>

namespace fs = std::filesystem;
using namespace std;

class AuthTest : public ::testing::Test {
protected:
    const string TEST_ROOT = "server_data_test/";
    void SetUp() override {
        if (fs::exists(TEST_ROOT)) fs::remove_all(TEST_ROOT);
        fs::create_directories(TEST_ROOT + "user");
    }
};

// Đăng ký
TEST_F(AuthTest, RegistrationFlow) {
    AuthManager auth(TEST_ROOT);
    string user = "user1", pass = "pass1", pubKey = "key1";

    // Đăng ký thành công
    ASSERT_TRUE(auth.registerUser(user, pass, pubKey));
    ASSERT_TRUE(fs::exists(TEST_ROOT + "user/" + user + ".json"));

    // Đăng ký trùng lặp (Fail)
    ASSERT_FALSE(auth.registerUser(user, "newpass", "newkey"));
}

// Đăng nhập & Token
TEST_F(AuthTest, LoginFlow) {
    AuthManager auth(TEST_ROOT);
    string user = "user2", pass = "pass2";
    auth.registerUser(user, pass, "key2");

    // Đăng nhập sai
    EXPECT_TRUE(auth.loginUser(user, "wrongpass").empty());
    EXPECT_TRUE(auth.loginUser("ghost", pass).empty());

    // Đăng nhập đúng
    string token = auth.loginUser(user, pass);
    ASSERT_FALSE(token.empty());

    // Validate Token
    EXPECT_EQ(auth.validateToken(token), user);
    EXPECT_TRUE(auth.validateToken("fake_token").empty());
}