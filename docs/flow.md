# Client-side Encryption (Tại ClientApp.cpp)

- Người dùng nhập nội dung ghi chú.

- ClientApp gọi CryptoManager::generateRandomKey() -> tạo NoteKey.

- Gọi CryptoManager::encryptAES(content, NoteKey) -> ra EncryptedData.

- Gửi EncryptedData lên Server.

- Quan trọng: Client phải lưu trữ NoteKey (hoặc buộc người dùng nhớ), vì Server không lưu key này.

# End-to-End Sharing (Tại ClientApp.cpp và Server.cpp)

- User A (Sender) muốn gửi Note ID 123 cho User B.

- A gửi request lên Server: "Cho tôi Public Key Diffie-Hellman của B".

- Server trả về Public Key của B (B đã upload lúc đăng ký).

- A dùng Private Key của mình + Public Key của B -> Tính ra SharedSecret.

- A lấy NoteKey của Note 123 -> Mã hóa nó bằng SharedSecret.

- A gửi EncryptedNoteKey lên Server, gắn tag "Cho User B".

- Khi B login, B tải EncryptedNoteKey -> Dùng Private Key của B + Public Key của A để tái tạo SharedSecret -> Giải mã ra NoteKey -> Dùng NoteKey giải mã ghi chú.