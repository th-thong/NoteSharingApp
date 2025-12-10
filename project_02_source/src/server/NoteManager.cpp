#include "NoteManager.h"
#include "CryptoManager.h"
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

const std::string STORAGE_DIR = "server_data/notes/";
const std::string SHARE_DIR = "server_data/shares/";


// -------------------------------------------------------------------
//                  Chuyễn đổi giữa Struct và JSON
// -------------------------------------------------------------------
json NoteMetadataToJson(const NoteMetadata& m) {
    return json{
        {"noteId", m.noteId}, {"owner", m.ownerUsername},
        {"path", m.filePath}, {"uploadTime", m.uploadTime},
        {"iv", m.iv}, {"tag", m.tag}, {"filename", m.originalFilename}
    };
}

NoteMetadata JsonToNoteMetadata(const json& j) {
    NoteMetadata m;
    m.noteId = j.value("noteId", ""); m.ownerUsername = j.value("owner", "");
    m.filePath = j.value("path", ""); m.uploadTime = j.value("uploadTime", 0);
    m.iv = j.value("iv", ""); m.tag = j.value("tag", "");
    m.originalFilename = j.value("filename", "unknown.bin");

    return m;
}

json ShareToJSON(const ShareMetadata& m) {
    return json{
        {"shareId", m.shareId}, {"linkedNoteId", m.linkedNoteId},
        {"created", m.createdTime}, {"expire", m.expirationTime},
        {"maxV", m.maxViews}, {"curV", m.currentViews},
        {"senderUsername",m.senderUsername},{"recipientUsername",m.recipientUsername},
        {"encryptedKey", m.encryptedKey}, {"keyIv",m.keyIv},
        {"keyTag",m.keyTag}
    };
}

ShareMetadata JSONToShare(const json& j) {
    ShareMetadata m;
    m.shareId = j.value("shareId", ""); m.linkedNoteId = j.value("linkedNoteId", "");
    m.createdTime = j.value("created", 0); m.expirationTime = j.value("expire", 0);
    m.maxViews = j.value("maxV", 0); m.currentViews = j.value("curV", 0);
    m.senderUsername = j.value("senderUsername", "");
    m.recipientUsername = j.value("recipientUsername", "");
    m.encryptedKey = j.value("encryptedKey", "");
    m.keyIv = j.value("keyIv", "");
    m.keyTag = j.value("keyTag", "");
    return m;
}


// -------------------------------------------------------------------
//                      Tạo ID Độc Nhất
// -------------------------------------------------------------------
std::string NoteManager::generateUniqueId() {
    const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, chars.size() - 1);
    std::string id = "";
    for (int i = 0; i < 12; ++i) id += chars[distribution(generator)];
    return id;
}

NoteManager::NoteManager() {
    if (!fs::exists("server_data")) fs::create_directory("server_data");
    if (!fs::exists(STORAGE_DIR)) fs::create_directories(STORAGE_DIR);
    if (!fs::exists(SHARE_DIR)) fs::create_directories(SHARE_DIR);
}

// -------------------------------------------------------------------
//              Lưu trữ và truy xuất Note
// -------------------------------------------------------------------

std::string NoteManager::saveNote(const std::string& owner,
    const std::string& encryptedContent,
    const std::string& iv,
    const std::string& tag,
    const std::string& filename) {
    NoteMetadata meta;
    meta.noteId = generateUniqueId();
    meta.ownerUsername = owner;
    meta.filePath = STORAGE_DIR + meta.noteId + ".bin";
    meta.uploadTime = std::time(nullptr);
    meta.iv = iv;
    meta.tag = tag;
    meta.originalFilename = filename;

    // DECODE Base64 về binary trước khi lưu
    std::vector<uint8_t> binaryData = CryptoManager::base64Decode(encryptedContent);

    // Lưu binary content
    std::ofstream binFile(meta.filePath, std::ios::binary);
    if (!binFile.is_open()) return "";
    binFile.write((char*)binaryData.data(), binaryData.size());
    binFile.close();

    // Lưu Metadata
    std::ofstream jsonFile(STORAGE_DIR + meta.noteId + ".json");
    jsonFile << NoteMetadataToJson(meta).dump(4);

    return meta.noteId;
}

// Hàm lấy nội dung dành cho chủ sở hữu note
bool NoteManager::getNoteContent(const std::string& noteId,
    std::string& outContent,
    std::string& outIV,
    std::string& outTag,
    std::string& outFilename)
{
    std::string notePath = STORAGE_DIR + noteId + ".json";
    if (!fs::exists(notePath)) return false;

    // Đọc Metadata
    std::ifstream nf(notePath);
    json nj; nf >> nj; nf.close();

    NoteMetadata note = JsonToNoteMetadata(nj);

    outIV = note.iv;
    outTag = note.tag;

    // --- LẤY TÊN FILE ---
    outFilename = note.originalFilename.empty() ? "downloaded_file.bin" : note.originalFilename;


    // Đọc Content
    std::ifstream bf(note.filePath, std::ios::binary | std::ios::ate);
    if (!bf.is_open()) return false;

    std::streamsize size = bf.tellg();
    bf.seekg(0, std::ios::beg);

    if (size <= 0) {
        outContent = "";
        return true;
    }

    std::vector<char> buffer(size);
    if (bf.read(buffer.data(), size)) {
        outContent.assign(buffer.begin(), buffer.end());
        return true;
    }

    return false;
}

// Lấy danh sách note của một user
std::vector<NoteMetadata> NoteManager::getNotesByUser(const std::string& username) {
    std::vector<NoteMetadata> result;
    if (!fs::exists(STORAGE_DIR)) return result;

    for (const auto& entry : fs::directory_iterator(STORAGE_DIR)) {
        if (entry.path().extension() == ".json") {
            try {
                std::ifstream f(entry.path());
                json j; f >> j; f.close();

                NoteMetadata meta = JsonToNoteMetadata(j);
                if (meta.ownerUsername == username) {
                    result.push_back(meta);
                }
            }
            catch (...) { continue; }
        }
    }
    return result;
}

// Xóa note
bool NoteManager::deleteNote(const std::string& noteId, const std::string& username) {
    std::string metadataPath = STORAGE_DIR + noteId + ".json";
    if (!fs::exists(metadataPath)) return false;

    try {
        std::ifstream f(metadataPath); json j; f >> j; f.close();
        NoteMetadata meta = JsonToNoteMetadata(j);

        if (meta.ownerUsername != username) return false;

        fs::remove(metadataPath);
        fs::remove(meta.filePath);

        return true;
    }
    catch (...) { return false; }
}

// -------------------------------------------------------------------
//              Chia sẻ Note    
// -------------------------------------------------------------------

std::string NoteManager::createShare(const std::string& noteId, const std::string& username, int duration, int maxViews) {
    std::string noteJsonPath = STORAGE_DIR + noteId + ".json";
    if (!fs::exists(noteJsonPath)) return "";

    std::ifstream f(noteJsonPath); json j; f >> j; f.close();
    NoteMetadata note = JsonToNoteMetadata(j);

    // Chỉ chủ sở hữu mới được tạo link
    if (note.ownerUsername != username) return "";

    ShareMetadata share;
    share.shareId = generateUniqueId();
    share.linkedNoteId = noteId;
    share.createdTime = std::time(nullptr);
    share.expirationTime = share.createdTime + duration;
    share.maxViews = maxViews;
    share.currentViews = 0;

    std::ofstream sFile(SHARE_DIR + share.shareId + ".json");
    sFile << ShareToJSON(share).dump(4);

    return share.shareId;
}

// Lấy nội dung note từ link chia sẻ
bool NoteManager::getSharedNoteContent(const std::string& shareId,
    std::string& outContent,
    std::string& outIV,
    std::string& outTag,
    ShareMetadata& outMeta,
    std::string& outFilename)
{
    std::string sharePath = SHARE_DIR + shareId + ".json";
    if (!fs::exists(sharePath)) return false;

    // 1. Đọc Share Info
    std::ifstream sf(sharePath);
    json sj;
    sf >> sj;
    sf.close();

    ShareMetadata share = JSONToShare(sj);


    time_t now = std::time(nullptr);
    if (now > share.expirationTime) {
        fs::remove(sharePath); // Xóa link hết hạn
        return false;
    }
    if (share.maxViews > 0 && share.currentViews >= share.maxViews) {
        fs::remove(sharePath); // Xóa link hết lượt xem
        return false;
    }

    // 3. Cập nhật lượt xem
    share.currentViews++;
    std::ofstream usf(sharePath);
    usf << ShareToJSON(share).dump(4);
    usf.close();

    // 4. Xuất Metadata ra ngoài
    outMeta = share;

    // 5. Đọc Note Gốc
    return getNoteContent(share.linkedNoteId, outContent, outIV, outTag, outFilename);
}

void NoteManager::cleanupExpiredNotes() {
    // Logic này có thể mở rộng để quét thư mục SHARE_DIR
    // Hiện tại chỉ demo, bạn có thể implement tương tự deleteNote
}


std::string NoteManager::createTargetedShare(
    const std::string& noteId,
    const std::string& sender,
    const std::string& recipient,
    const std::string& encKey,
    const std::string& iv,
    const std::string& tag,
    int duration,
    int maxViews)
{
    // Kiểm tra Note gốc có tồn tại không
    std::string noteJsonPath = STORAGE_DIR + noteId + ".json";
    if (!fs::exists(noteJsonPath)) {
        return ""; // File không tồn tại
    }

    // Đọc metadata của Note gốc để kiểm tra quyền sở hữu
    try {
        std::ifstream f(noteJsonPath);
        json j;
        f >> j;
        f.close();

        NoteMetadata note = JsonToNoteMetadata(j);

        // Nếu người yêu cầu share không phải là chủ sở hữu -> Từ chối
        if (note.ownerUsername != sender) {
            return "";
        }

        // Tạo Metadata cho bản chia sẻ
        ShareMetadata share;
        share.shareId = generateUniqueId(); // Sinh ID mới cho link share
        share.linkedNoteId = noteId;        // Trỏ về file gốc

        // Điền thông tin E2EE
        share.senderUsername = sender;
        share.recipientUsername = recipient;
        share.encryptedKey = encKey;        // Key AES đã được mã hóa bằng DH Secret
        share.keyIv = iv;
        share.keyTag = tag;

        // Điền thông tin giới hạn truy cập
        share.createdTime = std::time(nullptr);
        share.expirationTime = share.createdTime + duration;
        share.maxViews = maxViews;
        share.currentViews = 0;

        // Lưu Metadata chia sẻ vào file JSON
        std::string sharePath = SHARE_DIR + share.shareId + ".json";
        std::ofstream sFile(sharePath);

        if (sFile.is_open()) {
            sFile << ShareToJSON(share).dump(4);
            sFile.close();
            return share.shareId; // Trả về ID chia sẻ thành công
        }

    }
    catch (...) {
        return "";
    }

    return "";
}