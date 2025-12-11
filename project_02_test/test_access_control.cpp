#include <gtest/gtest.h>
#include "NoteManager.h"
#include <filesystem>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;
using namespace std;

class AccessTest : public ::testing::Test {
protected:
    const string TEST_ROOT = "server_data_test/";
    void SetUp() override {
        if (fs::exists(TEST_ROOT)) fs::remove_all(TEST_ROOT);
        fs::create_directories(TEST_ROOT + "notes");
        fs::create_directories(TEST_ROOT + "shares");
    }
};

// Kiểm tra lưu trữ vật lý
TEST_F(AccessTest, PersistenceCheck) {
    NoteManager mgr(TEST_ROOT);
    string noteId = mgr.saveNote("Alice", "content", "iv", "tag", "file.txt");
    
    ASSERT_FALSE(noteId.empty());
    ASSERT_TRUE(fs::exists(TEST_ROOT + "notes/" + noteId + ".bin"));
    ASSERT_TRUE(fs::exists(TEST_ROOT + "notes/" + noteId + ".json"));
}

// Kiểm tra hết hạn (Expiration)
TEST_F(AccessTest, ExpirationLimit) {
    NoteManager mgr(TEST_ROOT);
    string noteId = mgr.saveNote("Alice", "data", "iv", "tag", "f.txt");
    
    // Share tồn tại 1 giây
    string shareId = mgr.createTargetedShare(noteId, "Alice", "Bob", "k", "i", "t", 1, 10);
    
    string c, i, t, f; ShareMetadata m;
    // Ngay lập tức -> OK
    ASSERT_TRUE(mgr.getSharedNoteContent(shareId, c, i, t, m, f));

    // Chờ 2 giây -> Fail
    std::this_thread::sleep_for(std::chrono::seconds(2));
    ASSERT_FALSE(mgr.getSharedNoteContent(shareId, c, i, t, m, f));
    ASSERT_FALSE(fs::exists(TEST_ROOT + "shares/" + shareId + ".json"));
}

// Kiểm tra số lượt xem (Max Views)
TEST_F(AccessTest, MaxViewsLimit) {
    NoteManager mgr(TEST_ROOT);
    string noteId = mgr.saveNote("Alice", "data", "iv", "tag", "f.txt");
    
    // Max views = 2
    string shareId = mgr.createTargetedShare(noteId, "Alice", "Bob", "k", "i", "t", 3600, 2);
    
    string c, i, t, f; ShareMetadata m;
    
    // Lần 1: OK
    ASSERT_TRUE(mgr.getSharedNoteContent(shareId, c, i, t, m, f));
    // Lần 2: OK
    ASSERT_TRUE(mgr.getSharedNoteContent(shareId, c, i, t, m, f));
    // Lần 3: Fail
    ASSERT_FALSE(mgr.getSharedNoteContent(shareId, c, i, t, m, f));
}