enum class CommandType {
    REGISTER,
    LOGIN,
    UPLOAD_NOTE,
    DOWNLOAD_NOTE,
    SHARE_NOTE_REQUEST_KEY, // Bước 1 chia sẻ: Xin public key của người nhận
    SHARE_NOTE_SEND_KEY,    // Bước 2 chia sẻ: Gửi key ghi chú đã mã hóa
    GET_METADATA
};

struct Packet {
    CommandType cmd;
    char token[256];        // JWT Token để xác thực session
    int payloadSize;
    // Payload sẽ được gửi ngay sau Packet header này
};