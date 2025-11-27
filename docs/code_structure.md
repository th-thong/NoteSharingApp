E:.
│   .gitignore : Cấu hình Git bỏ qua các file build rác (.o, .exe, build/)
│   CMakeLists.txt : File cấu hình build dự án bằng CMake (hiện đại, đa nền tảng)
│   code_structure.md : Tài liệu mô tả kiến trúc và tổ chức code
│   flow.md : Tài liệu mô tả luồng đi của dữ liệu (Flowchart)
│   Makefile : File kịch bản để biên dịch nhanh bằng lệnh 'make' (trên Linux/G++)
│   
├───project_02_report : Thư mục chứa báo cáo đồ án (file PDF)
│       .gitkeep :
│       
├───project_02_source : Thư mục chứa toàn bộ mã nguồn chương trình
│   ├───include : Chứa các file header (.h) định nghĩa giao diện và cấu trúc
│   │   ├───client : Header riêng cho ứng dụng Client
│   │   │       ClientApp.h : Khai báo lớp xử lý logic chính của Client (Menu, gửi/nhận lệnh)
│   │   │
│   │   ├───common : Header dùng chung cho cả Client và Server (để đồng bộ)
│   │   │       Protocol.h : Định nghĩa cấu trúc gói tin (Packet) và các mã lệnh (CMD Enum)
│   │   │       Utils.h : Các hàm tiện ích bổ trợ (Log, chuyển đổi Hex/String, Time)
│   │   │
│   │   ├───crypto : Header cho module bảo mật
│   │   │       CryptoManager.h : Khai báo các hàm bọc thư viện OpenSSL (AES, SHA, Diffie-Hellman)
│   │   │
│   │   └───server : Header riêng cho ứng dụng Server
│   │           AuthManager.h : Quản lý xác thực người dùng (Đăng ký, Đăng nhập, lưu Token)
│   │           NoteManager.h : Quản lý ghi chú (Lưu trữ file, kiểm tra thời gian hết hạn)
│   │           Server.h : Khai báo lớp Server (Mở socket, vòng lặp lắng nghe kết nối)
│   │
│   └───src : Chứa các file mã nguồn thực thi (.cpp) cài đặt logic chi tiết
│       ├───client : Mã nguồn phía máy khách
│       │       ClientApp.cpp : Thực thi logic hiển thị Menu, xử lý input và gọi CryptoManager
│       │       main_client.cpp : Điểm bắt đầu (Entry point) của chương trình Client
│       │
│       ├───crypto : Mã nguồn module bảo mật
│       │       CryptoManager.cpp : Gọi trực tiếp thư viện OpenSSL để thực hiện mã hóa/giải mã/băm
│       │
│       └───server : Mã nguồn phía máy chủ
│               AuthManager.cpp : Thực thi logic kiểm tra mật khẩu, tạo hash và quản lý session
│               main_server.cpp : Điểm bắt đầu (Entry point) của chương trình Server
│               NoteManager.cpp : Thực thi việc ghi/đọc file mã hóa trên ổ cứng và xóa khi hết hạn
│               Server.cpp : Thiết lập kết nối mạng, nhận gói tin và điều phối sang các Manager
│
└───project_02_test : Thư mục chứa các script hoặc file dữ liệu để kiểm thử (Unit Test)
        .gitkeep