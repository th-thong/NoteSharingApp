/*
1. Menu Loop: 

2. Hiện các lựa chọn: 1. Đăng nhập, 2. Đăng ký...
    Xử lý Đăng nhập/Đăng ký:
    Nhập user/pass từ bàn phím.
    Tạo gói tin, Gửi Server, Chờ phản hồi.
    Nếu đăng nhập thành công: Lưu Token lại để dùng cho các request sau.

3. Xử lý Upload Note:
    Bước 1: Đọc file text từ máy tính (ví dụ hello.txt).
    Bước 2: Sinh một khóa ngẫu nhiên NoteKey (AES Key).
    Bước 3: Gọi CryptoManager::encryptAES để mã hóa nội dung file.
    Bước 4: Gửi Ciphertext (nội dung đã mã hóa) lên Server.Lưu ý: Client phải tự nhớ NoteKey hoặc lưu NoteKey lại đâu đó, Server không biết key này.
*/