🔐 Flask Secure Chat App
Ứng dụng web đơn giản mô phỏng hệ thống nhắn tin bảo mật giữa người dùng với nhau bằng Python và Flask.

💡 Tính năng chính
Đăng ký và đăng nhập tài khoản người dùng.
![image](https://github.com/user-attachments/assets/e8a7814b-4bb9-4559-97de-8817b3057f7d)

Mỗi người dùng có một cặp khóa RSA riêng.

Gửi tin nhắn sử dụng mã hóa 3DES:

Khóa 3DES được trao đổi an toàn qua RSA và chữ ký số.

Tin nhắn được ký và xác minh tính toàn vẹn bằng SHA-256 và RSA.

Giao diện đẹp, dễ sử dụng (HTML + CSS animation).

🛠 Công nghệ sử dụng
Python + Flask

pycryptodome cho RSA, 3DES, SHA-256

HTML/CSS thuần (đăng ký, xác minh tin nhắn)
