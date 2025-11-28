# 1. Phân vai trò chi tiết
## Thành viên 1: Trưởng nhóm Kỹ thuật & Bảo mật (The Cryptographer)

Trọng tâm: Làm việc với thư viện OpenSSL, chịu trách nhiệm về tính đúng đắn của các thuật toán mã hóa. Đây là phần khó nhất về mặt kỹ thuật nhưng code sẽ gọn.

Nhiệm vụ chính:

- Cài đặt CryptoManager.cpp:

- Hàm băm mật khẩu (SHA-256 hoặc Argon2) kết hợp với Salt để bảo vệ mật khẩu.

- Hàm mã hóa/giải mã AES (AES-256-GCM hoặc CBC) cho file ghi chú.

- Hàm tạo và trao đổi khóa Diffie-Hellman cho tính năng chia sẻ.

- Viết Unit Test cho module Crypto để đảm bảo dữ liệu mã hóa xong giải mã ra y hệt bản gốc.

- File phụ trách: src/crypto/*, tests/TestCrypto.cpp.

## Thành viên 2: Backend Developer (The Server Master)
Trọng tâm: Quản lý logic nghiệp vụ, lưu trữ dữ liệu và kiểm soát truy cập.

Nhiệm vụ chính:

- Xây dựng Server.cpp: Mở socket, lắng nghe kết nối, điều phối luồng request từ nhiều client.

- Cài đặt AuthManager.cpp: Xử lý đăng ký, đăng nhập, và kiểm tra Token/Session.


- Cài đặt NoteManager.cpp:

- Lưu trữ các file đã mã hóa (blob) lên ổ cứng server.

- Kiểm tra logic thời gian hết hạn (Time-sensitive access) - tự động chặn truy cập hoặc xóa file khi hết giờ.


- Xử lý lưu trữ và phân phối Public Key cho tính năng chia sẻ.

- File phụ trách: src/server/*, src/common/Protocol.h (phối hợp với TV3).

## Thành viên 3: Frontend & Integration (The Client Commander)
Trọng tâm: Trải nghiệm người dùng, kết nối mạng và tích hợp các module lại với nhau.

Nhiệm vụ chính:

- Xây dựng ClientApp.cpp & main_client.cpp:

- Thiết kế giao diện dòng lệnh (CLI Menu) cho người dùng tương tác.

- Thực hiện logic kết nối Socket tới Server.

- Là người gọi các hàm của TV1 để mã hóa dữ liệu trước khi gửi cho TV2.

- Xử lý luồng chia sẻ: Xin Public Key -> Tính Shared Secret (gọi hàm TV1) -> Gửi Key (gọi hàm TV2).

- Viết kịch bản kiểm thử luồng người dùng (User Acceptance Testing).


- File phụ trách: src/client/*, src/common/Utils.h.

# Quy trình phối hợp (Workflow)

- Giai đoạn 1: Khởi tạo (Ngày 1-2)

Cả 3 người: Thống nhất file Protocol.h. Đây là bước quan trọng nhất. Phải chốt xem Client gửi gói tin gì (ID bao nhiêu, cấu trúc struct thế nào) thì Server mới hiểu được.

TV1: Viết khung (skeleton) cho các hàm Crypto (chưa cần code thật, chỉ cần return dữ liệu giả) để TV3 có cái gọi hàm.

- Giai đoạn 2: Phát triển độc lập (Ngày 3-10)

TV1: Tập trung implement OpenSSL cho AES và Diffie-Hellman.

TV2: Xây dựng Server xử lý Login/Register và lưu file (chưa cần quan tâm nội dung file là gì).

- TV3: Xây dựng Menu và luồng gửi/nhận dữ liệu Socket.

Giai đoạn 3: Tích hợp (Ngày 11-15)

Ghép code Crypto thật của TV1 vào Client của TV3.

Test luồng End-to-End: Client A mã hóa -> Gửi Server -> Server lưu -> Client A tải về giải mã.

Test tính năng chia sẻ: Client A chia sẻ cho Client B (sử dụng Diffie-Hellman).