#ifndef NOTE_MANAGER_H
#define NOTE_MANAGER_H

#include <string>
#include <ctime>
#include <vector>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

struct NoteMetadata {
    std::string noteId;
    std::string ownerUsername;
    std::string filePath;
    time_t uploadTime;
    std::string originalFilename;
    std::string iv;
    std::string tag;
};

struct ShareMetadata {
    std::string shareId;     // ID của link chia sẻ 
    std::string linkedNoteId;// Trỏ về Note gốc
    std::string senderUsername;    // Người gửi
    std::string recipientUsername; // Người nhận
    std::string encryptedKey;      // NoteKey được mã hóa bằng SharedSecret
    std::string keyIv;             // IV dùng để mã hóa NoteKey
    std::string keyTag;            // Tag dùng để mã hóa NoteKey
    time_t createdTime;
    time_t expirationTime;
    int maxViews;
    int currentViews;
};

json NoteMetadataToJson(const NoteMetadata& m);
NoteMetadata JsonToNoteMetadata(const json& j);
json ShareToJSON(const ShareMetadata& m);
ShareMetadata JSONToShare(const json& j);
class NoteManager {
public:
    NoteManager(std::string rootPath = "server_data/");


    std::string saveNote(
        const std::string& owner, 
        const std::string& encryptedContent, 
        const std::string& iv,
        const std::string& tag, 
        const std::string& filename
    );

    bool getNote(
        const std::string& noteId, 
        std::string& outEncryptedContent
    );

    std::string createShare(
        const std::string& noteId,
        const std::string& username, 
        int duration, int maxViews
    );

    bool getSharedNoteContent(
        const std::string& shareId,
        std::string& outContent,
        std::string& outIV,
        std::string& outTag,
        ShareMetadata& outMeta,
        std::string& outFilename
    );


    std::vector<NoteMetadata> getNotesByUser(const std::string& username);

    bool deleteNote(const std::string& noteId, const std::string& username);

    bool enableSharing(const std::string& noteId, const std::string& username, int durationSeconds, int maxViews);

    bool getNoteContent(
        const std::string& noteId,
        std::string& outContent,
        std::string& outIV,
        std::string& outTag,
        std::string& outFilename
    );

    std::string createTargetedShare(
        const std::string& noteId,
        const std::string& sender,
        const std::string& recipient,
        const std::string& encKey,
        const std::string& iv,
        const std::string& tag,
        int duration,
        int maxViews);
private:
    std::string generateUniqueId();
    std::string NOTE_DIR;
    std::string SHARE_DIR;

};

#endif