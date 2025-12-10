#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>

enum class CommandType : uint8_t {
    REGISTER = 1,
    LOGIN,
    UPLOAD_NOTE,
    DOWNLOAD_NOTE,
    DELETE_NOTE,

    // --- Chia sẻ ---
    GET_METADATA,       // Lấy danh sách note
    GET_PUBLIC_KEY,     // Lấy PubKey để mã hóa/giải mã E2EE
	SHARE_NOTE,         // Chia sẻ note
    DOWNLOAD_SHARED,    // Tải note được chia sẻ

    CMD_SUCCESS,
    CMD_ERROR,
    CMD_DATA
};

// Đảm bảo không có padding giữa các trường
#pragma pack(push, 1) 
struct PacketHeader {
    CommandType cmd;
    uint32_t payloadSize;
    char token[512];
};
#pragma pack(pop)

#endif