# Cách chạy ứng dụng

1. Build và chạy server, client
- Chạy lệnh ```docker-compose up -d --build``` để build và chạy
- Xem log của server ```docker logs -f note_server``` hoặc client ```docker logs -f note_client```
- Vào máy client bằng lệnh ```docker exec -it note_client bash```, sau đó chạy lệnh ```./client_app``` để khởi chạy client
- Khởi động lại máy ```docker-compose restart```