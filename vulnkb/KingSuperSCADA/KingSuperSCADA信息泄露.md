# KingSuperSCADA信息泄露

KingSuperSCADA ｜ 信息泄露 ｜ —
- **请求**：`GET /user.json HTTP/1.1`
- **响应特征**：200 ^(?=.*?name)(?=.*?password).*?$