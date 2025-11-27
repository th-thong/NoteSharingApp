#ifndef NOTE_MANAGER_H
#define NOTE_MANAGER_H

#include <string>
#include <map>
#include <ctime>

struct NoteMetadata {
    std::string noteId;
    std::string ownerUsername;
    std::string filePath;       // Đường dẫn lưu file mã hóa trên ổ cứng server
    time_t uploadTime;
    time_t expirationTime;      // Thời điểm hết hạn
    int maxViews;               // Số lượt xem tối đa (optional)
    int currentViews;
    bool isShared;
};

class NoteManager {
private:
    std::map<std::string, NoteMetadata> notesDB; // Key: noteId

public:
    // Lưu metadata và file (file content đã được mã hóa ở client)
    bool saveNote(const std::string& owner, const std::string& encryptedContent, int durationSeconds);
    
    // Lấy ghi chú. Phải kiểm tra expiry trước khi trả về.
    // Nếu hết hạn -> return false và xóa file.
    bool getNote(const std::string& noteId, std::string& outEncryptedContent);
    
    // Tạo URL/ID tạm thời
    std::string generateUniqueLink();
    
    // Clean up định kỳ các note hết hạn
    void cleanupExpiredNotes();
};

#endif