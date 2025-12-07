#include "NoteManager.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <random>
#include <ctime>
#include <sstream>

using namespace std;
using json = nlohmann::json;
namespace fs = std::filesystem;

// Thư mục lưu trữ (đảm bảo trùng khớp với Docker mount)
const std::string STORAGE_DIR = "database_storage";

// --- Helper Functions ---

// Hàm chuyển Struct sang JSON
json NoteMetadataToJson(const NoteMetadata& metadata) {
    json j;
    j["noteId"]         = metadata.noteId;
    j["ownerUsername"]  = metadata.ownerUsername;
    j["filePath"]       = metadata.filePath;
    j["uploadTime"]     = metadata.uploadTime; 
    j["expirationTime"] = metadata.expirationTime;
    j["maxViews"]       = metadata.maxViews;
    j["currentViews"]   = metadata.currentViews;
    j["isShared"]       = metadata.isShared;
    return j;
}

// Hàm chuyển JSON sang Struct
NoteMetadata JsonToNoteMetadata(const json& j) {
    NoteMetadata m;
    m.noteId = j.value("noteId", "");
    m.ownerUsername = j.value("ownerUsername", "");
    m.filePath = j.value("filePath", "");
    m.uploadTime = j.value("uploadTime", 0);
    m.expirationTime = j.value("expirationTime", 0);
    m.maxViews = j.value("maxViews", 0);
    m.currentViews = j.value("currentViews", 0);
    m.isShared = j.value("isShared", false);
    return m;
}

// --- Class Implementation ---

NoteManager::NoteManager() {
    // Tạo thư mục lưu trữ nếu chưa có
    if (!fs::exists(STORAGE_DIR)) {
        fs::create_directories(STORAGE_DIR);
    }
}

// Hàm tạo ID ngẫu nhiên (URL ngắn)
std::string NoteManager::generateUniqueLink() {
    const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, chars.size() - 1);

    std::string id = "";
    // Tạo ID độ dài 12 ký tự
    for (int i = 0; i < 12; ++i) {
        id += chars[distribution(generator)];
    }
    return id;
}

// Hàm lưu Note (trả về ID của note vừa tạo)
std::string NoteManager::saveNote(const std::string& owner, const std::string& encryptedContent, int durationSeconds, int maxViews) {
    // 1. Tạo Metadata mới
    NoteMetadata metadata;
    metadata.noteId = generateUniqueLink(); [cite_start]// [cite: 43] Tạo ID duy nhất
    metadata.ownerUsername = owner;
    
    // Đường dẫn file nội dung (Binary)
    metadata.filePath = STORAGE_DIR + "/" + metadata.noteId + ".bin";
    
    metadata.uploadTime = std::time(nullptr);
    metadata.expirationTime = metadata.uploadTime + durationSeconds; [cite_start]// [cite: 27] Tính thời gian hết hạn
    metadata.maxViews = maxViews; [cite_start]// [cite: 27] Giới hạn số lượt xem
    metadata.currentViews = 0;
    metadata.isShared = false;

    // Đường dẫn file Metadata (JSON)
    std::string metadataPath = STORAGE_DIR + "/" + metadata.noteId + ".json";

    // 2. Lưu File Metadata (JSON)
    json j = NoteMetadataToJson(metadata);
    std::ofstream metaFile(metadataPath);
    if (metaFile.is_open()) {
        metaFile << j.dump(4);
        metaFile.close();
    } else {
        return ""; // Lỗi không ghi được
    }

    // 3. Lưu File Nội dung (Encrypted Blob)
    // QUAN TRỌNG: Phải dùng ios::binary vì encryptedContent chứa byte rác/null
    std::ofstream contentFile(metadata.filePath, std::ios::binary);
    if (contentFile.is_open()) {
        contentFile.write(encryptedContent.data(), encryptedContent.size());
        contentFile.close();
    } else {
        return "";
    }

    return metadata.noteId;
}

// Hàm lấy Note (Có kiểm tra logic Hết hạn và View)
bool NoteManager::getNote(const std::string& noteId, std::string& outEncryptedContent) {
    std::string metadataPath = STORAGE_DIR + "/" + noteId + ".json";

    // 1. Kiểm tra file metadata có tồn tại không
    if (!fs::exists(metadataPath)) return false;

    // 2. Đọc Metadata
    std::ifstream metaFile(metadataPath);
    json j;
    metaFile >> j;
    metaFile.close();

    NoteMetadata metadata = JsonToNoteMetadata(j);

    [cite_start]// 3. Kiểm tra logic bảo mật [cite: 27, 44]
    
    // A. Kiểm tra thời gian hết hạn
    time_t now = std::time(nullptr);
    if (now > metadata.expirationTime) {
        std::cout << "[NOTE] Note expired. Deleting..." << std::endl;
        // Xóa file nếu hết hạn (tự động dọn dẹp ngay khi truy cập)
        fs::remove(metadataPath);
        fs::remove(metadata.filePath);
        return false;
    }

    // B. Kiểm tra số lượt xem (nếu có giới hạn)
    if (metadata.maxViews > 0 && metadata.currentViews >= metadata.maxViews) {
        std::cout << "[NOTE] Max views reached. Deleting..." << std::endl;
        fs::remove(metadataPath);
        fs::remove(metadata.filePath);
        return false;
    }

    // 4. Nếu hợp lệ: Đọc nội dung file mã hóa
    std::ifstream contentFile(metadata.filePath, std::ios::binary);
    if (!contentFile.is_open()) return false;

    // Đọc toàn bộ file vào string buffer
    std::stringstream buffer;
    buffer << contentFile.rdbuf();
    outEncryptedContent = buffer.str();
    contentFile.close();

    // 5. Cập nhật lượt xem (Current Views) và lưu lại Metadata
    metadata.currentViews++;
    
    // Nếu đây là lần xem cuối cùng (vừa đủ maxViews), ta có thể xóa luôn hoặc để lần sau xóa
    // Ở đây chọn cách cập nhật để lần sau truy cập sẽ bị chặn
    std::ofstream updateMeta(metadataPath);
    updateMeta << NoteMetadataToJson(metadata).dump(4);
    updateMeta.close();

    return true;
}

// Hàm dọn dẹp định kỳ (chạy background hoặc khi khởi động server)
void NoteManager::cleanupExpiredNotes() {
    time_t now = std::time(nullptr);
    int deletedCount = 0;

    // Duyệt qua tất cả file trong thư mục storage
    for (const auto& entry : fs::directory_iterator(STORAGE_DIR)) {
        if (entry.path().extension() == ".json") {
            try {
                std::ifstream f(entry.path());
                json j;
                f >> j;
                f.close();

                time_t expTime = j["expirationTime"];
                
                // Nếu hết hạn -> Xóa cả json và bin
                if (now > expTime) {
                    std::string binPath = j["filePath"];
                    fs::remove(entry.path()); // Xóa .json
                    fs::remove(binPath);      // Xóa .bin
                    deletedCount++;
                }
            } catch (...) {
                continue; // Bỏ qua file lỗi
            }
        }
    }
    if (deletedCount > 0) {
        std::cout << "[CLEANUP] Deleted " << deletedCount << " expired notes." << std::endl;
    }
}