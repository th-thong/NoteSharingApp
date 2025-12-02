1. Client-side Encryption (Mã hóa phía máy khách)
Đây là quy trình biến nội dung ghi chú thành dữ liệu "vô nghĩa" trước khi nó rời khỏi máy tính của người dùng. Server chỉ đóng vai trò là kho chứa và hoàn toàn không hiểu nội dung file.


Diễn giải chi tiết:

Bước 1: Soạn thảo (Input): Người dùng mở ứng dụng ClientApp và nhập nội dung ghi chú (ví dụ: "Mật khẩu ngân hàng là 1234"). Tại thời điểm này, dữ liệu vẫn là dạng văn bản rõ (plaintext) nằm trên RAM của máy khách.

Bước 2: Sinh khóa ngẫu nhiên (Key Generation):

Ngay khi người dùng nhấn "Lưu", ClientApp sẽ gọi hàm CryptoManager::generateRandomKey().

Hàm này sinh ra một chuỗi nhị phân ngẫu nhiên (ví dụ 256-bit). Chúng ta gọi đây là NoteKey (Khóa ghi chú).

Lưu ý: Mỗi ghi chú sẽ có một NoteKey riêng biệt.

Bước 3: Mã hóa (Encryption):

ClientApp sử dụng thuật toán AES (như AES-256-GCM).

Đầu vào: Nội dung ghi chú + NoteKey.

Đầu ra: Một chuỗi byte lộn xộn gọi là EncryptedData (Bản mã).

Bước 4: Tải lên (Upload):

Client gửi EncryptedData lên Server. Server lưu chuỗi này vào ổ cứng.

Bước 5: Quản lý khóa (Key Management):

Đây là bước tối quan trọng. Server không bao giờ nhận được NoteKey.

Client phải tự lưu NoteKey này lại (ví dụ: lưu vào file cục bộ được bảo vệ, hoặc hiển thị ra màn hình yêu cầu người dùng copy lại để lần sau muốn mở thì paste vào). Nếu mất NoteKey, ghi chú coi như mất vĩnh viễn.

2. End-to-End Sharing (Chia sẻ đầu cuối bảo mật)
Đây là quy trình cho phép User A gửi "chìa khóa" của ghi chú cho User B mà không sợ bị Server hay kẻ gian nghe lén. Chúng ta sử dụng giao thức trao đổi khóa Diffie-Hellman (DH).

Giả định trước: Khi đăng ký tài khoản, mỗi User (A và B) đều đã sinh một cặp khóa (Private Key - bí mật, Public Key - công khai) và đã gửi Public Key lên Server để lưu trữ.

Diễn giải chi tiết quy trình chia sẻ:

Bước 1: Yêu cầu thông tin (Discovery):

User A muốn chia sẻ ghi chú (đang được khóa bởi NoteKey) cho User B.

A không thể gửi thẳng NoteKey qua mạng. A gửi yêu cầu lên Server: "Cho tôi xin Public Key của User B".

Bước 2: Phản hồi thông tin:

Server tìm trong cơ sở dữ liệu và trả về Public Key của B cho A.

Bước 3: Tính toán bí mật chung (The Magic Math):

Tại máy của A: A sử dụng Private Key của A kết hợp với Public Key của B (vừa tải về).

Thông qua thuật toán Diffie-Hellman, phép tính này tạo ra một chuỗi bí mật gọi là SharedSecret.

Đặc điểm: Chỉ có A và B mới tính ra được chuỗi này. Server không có Private Key của ai cả nên không tính được.

Bước 4: Đóng gói chìa khóa (Key Wrapping):

A dùng SharedSecret làm khóa để mã hóa cái NoteKey ban đầu.

Kết quả tạo ra một gói tin nhỏ gọi là EncryptedNoteKey.

Bước 5: Vận chuyển (Transfer):

A gửi EncryptedNoteKey lên Server kèm lời nhắn: "Cái này dành cho B đối với ghi chú 123".

Server lưu gói tin này lại nhưng không mở được (vì không có SharedSecret).

Bước 6: Nhận hàng (Receive):

Khi User B đăng nhập, B thấy thông báo có ghi chú được chia sẻ. B tải EncryptedNoteKey về máy.

Đồng thời, B xin Server Public Key của A.

Bước 7: Tái tạo bí mật chung (Re-calculation):

Tại máy của B: B sử dụng Private Key của B kết hợp với Public Key của A.

Theo tính chất toán học của Diffie-Hellman, kết quả phép tính này ra đúng cái SharedSecret mà A đã tạo ở Bước 3.

Bước 8: Mở gói chìa khóa (Unwrapping):

B dùng SharedSecret để giải mã EncryptedNoteKey.

Kết quả: B lấy được NoteKey gốc.

Bước 9: Đọc ghi chú:

Cuối cùng, B dùng NoteKey để giải mã nội dung ghi chú (EncryptedData) tải từ Server về và đọc được nội dung gốc.

Tóm tắt đơn giản: Server giống như một người đưa thư mù. A bỏ "chìa khóa két sắt" (NoteKey) vào một "cái hộp đặc biệt" (EncryptedNoteKey) mà chỉ có A và B mới biết cách mở (nhờ SharedSecret). Server chuyển cái hộp đó cho B, nhưng không bao giờ mở được hộp.