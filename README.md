# Document
- Các tài liệu nằm ở folder docs


# Cách chạy ứng dụng

**Note: Các lệnh chạy hiện tại có thể sai do chưa có code**

- Chạy lệnh ```docker-compose up -d --build``` để build và chạy
- Xem log của server ```docker logs -f note_server``` hoặc client ```docker logs -f note_client```
- Vào máy client bằng lệnh ```docker exec -it note_client bash```, sau đó chạy lệnh ```./client_app``` để khởi chạy client
- Khởi động lại máy ```docker-compose restart```