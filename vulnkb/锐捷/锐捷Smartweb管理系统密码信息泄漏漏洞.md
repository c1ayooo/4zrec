# 锐捷Smartweb管理系统密码信息泄漏漏洞

- **系统**：锐捷　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app.name="Ruijie 锐捷 Smartweb"`
- **请求**：`http://xx.xx.xx.xx/web/xml/webuser-auth.xml`

**请求体 / payload**
```
1. 使用默认口令`guest/guest`登录系统
2. 使用poc获取管理员`admin`账号密码
3. base64解码后获取账号密码
4. 使用获取的管理账号admin登录系统
```

**其他**
- 锐捷 Smartweb管理系统密码信息泄漏漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 锐捷网络股份有限公司 无线smartweb管理系统