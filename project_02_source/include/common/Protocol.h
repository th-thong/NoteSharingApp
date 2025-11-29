#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>

enum class CommandType : uint8_t {
    // --- Lệnh từ Client gửi lên ---
    REGISTER = 1,
    LOGIN,
    UPLOAD_NOTE,
    DOWNLOAD_NOTE,
    
    // --- Nhóm lệnh chia sẻ (End-to-End) ---
    SHARE_REQUEST_PUBKEY,   // Bước 1: Xin public key của user B
    SHARE_SEND_ENCRYPTED_KEY, // Bước 2: Gửi key note đã mã hóa cho user B
    
    GET_METADATA,           // Lấy danh sách ghi chú
    
    // --- Phản hồi từ Server gửi về ---
    CMD_SUCCESS,            // Thành công (Payload rỗng hoặc chứa data)
    CMD_ERROR,              // Thất bại (Payload chứa thông báo lỗi text)
    CMD_DATA                // Phản hồi chứa dữ liệu (ví dụ nội dung file tải về)
};

// Sử dụng pragma pack để ép struct không có byte thừa (padding)
#pragma pack(push, 1) 
struct PacketHeader {
    CommandType cmd;
    uint32_t payloadSize;
    char token[512];
};
#pragma pack(pop)

#endif